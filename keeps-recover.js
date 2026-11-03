#!/usr/bin/env node
// keeps-recover: open the sealed copy of Key C from a Keeps recovery kit, OFFLINE.
//
// Only type your words into the Keeps app or the offline recovery tool. Never into a website.
//
// One file, Node.js standard library only ('crypto', 'fs'). No network code: this file
// never loads 'net', 'http', 'https', 'http2', 'dns', 'tls', 'dgram', 'child_process'
// or 'worker_threads', never calls fetch, and refuses to start if a network-ish flag,
// Node option or environment variable is present (see refuseNetwork()).
//
// Format (keeps-native CairnVault v2, also reads v1):
//   [0..4) "KCRN" | [4] version 1|2 | [5] kdf=1 scrypt | [6] log2N | [7..11) r LE32
//   [11..15) p LE32 | [15] saltLen=16 | [16..32) salt | nonce(12) || ciphertext(32) || tag(16)
//   key = scrypt(NFC(passphrase), salt, N=2^log2N, r, p, 32) ; AES-256-GCM, AAD = header (v2)
// The plaintext is the 32-byte Ed25519 seed of Key C. Output: a Solana CLI keypair file
// (JSON array of the 64-byte seed||pubkey), mode 600, and the public key in base58.
'use strict';

const crypto = require('crypto');
const fs = require('fs');

const VERSION = '1.0.0';
const RULE = 'Only type your words into the Keeps app or the offline recovery tool. Never into a website.';

const EXIT = { OK: 0, WRONG_WORDS: 1, USAGE: 2, NETWORK: 3, BAD_BLOB: 4, MISMATCH: 5, OUTPUT: 6 };

class Fail extends Error {
  constructor(code, msg) { super(msg); this.code = code; }
}

// ---------------------------------------------------------------- KT2: no network
const NET_FLAG = /^--?(rpc|rpc-url|url|u|network|cluster|host|port|proxy|online|fetch|download|update|upload|server|serve|listen|http.*|https.*|ws.*|wss.*|dns.*|endpoint|api.*|webhook|telemetry|send|submit|connect)(=.*)?$/i;
const NET_ENV = [
  /proxy/i,                                   // HTTP_PROXY, https_proxy, ALL_PROXY, NO_PROXY, ...
  /^NODE_OPTIONS$/, /^NODE_EXTRA_CA_CERTS$/, /^NODE_TLS_/, /^NODE_USE_ENV_PROXY$/,
  /^NODE_INSPECT/, /^NODE_REPL_EXTERNAL_MODULE$/, /^NODE_DEBUG_NATIVE$/,
  /^SSL_CERT_(FILE|DIR)$/, /^SSLKEYLOGFILE$/,
  /RPC/i, /(^|_)URL$/i, /ENDPOINT/i,
];

function refuseNetwork(argv, env, execArgv) {
  const why = [];
  if (execArgv.length) why.push('Node runtime options (' + execArgv.join(' ') + ')');
  for (const a of argv) {
    if (NET_FLAG.test(a) || /:\/\//.test(a)) why.push('argument "' + a.split('=')[0] + '"');
  }
  for (const name of Object.keys(env)) {
    if (NET_ENV.some((re) => re.test(name))) why.push('environment variable ' + name);
  }
  return why;
}

// ---------------------------------------------------------------- blob parsing
const MAGIC = Buffer.from('KCRN', 'ascii');
const SALT_LEN = 16;
const HEADER_LEN = 16 + SALT_LEN;
const BOX_LEN = 12 + 32 + 16;
const MAX_SCRYPT_MEM = 256 * 1024 * 1024;   // same ceiling as the app (Scrypt.maximumMemoryBytes)

// Accepts the kit's text: optional "KCRN2:" / "KCRN1:" label, then base64 or base64url,
// whitespace and line breaks ignored. Returns the raw blob bytes.
function decodeBlobText(text) {
  let t = String(text).replace(/\s+/g, '');
  t = t.replace(/^KCRN[12]:/i, '');
  if (!t) throw new Fail(EXIT.BAD_BLOB, 'No sealed copy given.');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) {
    throw new Fail(EXIT.BAD_BLOB, 'The sealed copy has characters that are not base64. Check for typos (it is the text under the QR code).');
  }
  const b = Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  return b;
}

// Mirrors CairnVault.validatedEnvelope: every attacker-controlled field is bounded
// before any KDF work or allocation.
function parseBlob(b) {
  if (b.length < 16 || !b.subarray(0, 4).equals(MAGIC)) throw new Fail(EXIT.BAD_BLOB, 'This is not a Keeps sealed copy (bad magic). Check you copied the whole text.');
  const version = b[4];
  if (version !== 1 && version !== 2) throw new Fail(EXIT.BAD_BLOB, 'Unknown sealed-copy version ' + version + '. You may need a newer keeps-recover.');
  if (b[5] !== 1) throw new Fail(EXIT.BAD_BLOB, 'Unknown key-derivation id ' + b[5] + '.');
  const log2N = b[6];
  const r = b.readUInt32LE(7);
  const p = b.readUInt32LE(11);
  if (log2N < 10 || log2N > 20 || r < 1 || r > 32 || p < 1 || p > 16) throw new Fail(EXIT.BAD_BLOB, 'Unsupported scrypt parameters in the sealed copy.');
  if (b[15] !== SALT_LEN) throw new Fail(EXIT.BAD_BLOB, 'Unsupported salt length in the sealed copy.');
  if (b.length !== HEADER_LEN + BOX_LEN) throw new Fail(EXIT.BAD_BLOB, 'The sealed copy is the wrong length (' + b.length + ' bytes, expected ' + (HEADER_LEN + BOX_LEN) + '). Check you copied all of it.');
  const N = 2 ** log2N;
  if (N * 128 * r > MAX_SCRYPT_MEM) throw new Fail(EXIT.BAD_BLOB, 'The sealed copy asks for too much memory.');
  return {
    version, log2N, r, p, N,
    salt: b.subarray(16, HEADER_LEN),
    header: b.subarray(0, HEADER_LEN),
    nonce: b.subarray(HEADER_LEN, HEADER_LEN + 12),
    ct: b.subarray(HEADER_LEN + 12, HEADER_LEN + 44),
    tag: b.subarray(HEADER_LEN + 44, HEADER_LEN + 60),
  };
}

// ---------------------------------------------------------------- passphrase
// The app (SelfCustody.canonicalPassphrase + CairnPhrase.canonical + CairnVault.deriveKey):
//   six EFF words -> NFC(lowercase, trimmed, single-space-joined); anything else -> NFC(verbatim).
// We do not ship the 7,776-word list; instead we try the canonical form first and, only if it
// differs from the verbatim input and fails, the verbatim form. Everything the app opens, this
// opens. It is slightly more tolerant than the app: a free-form passphrase typed with different
// case or spacing also opens (the app would refuse it). That helps the owner and costs nothing:
// an attacker never needs this tool to guess.
const ASCII_WS = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20]);

function isAscii(buf) { for (const c of buf) if (c > 0x7f) return false; return true; }

// Returns an array of Buffers (candidates), each owned by the caller (wipe after use).
// ASCII input never becomes a JS string, so it can be wiped.
function passphraseCandidates(raw) {
  if (isAscii(raw)) {
    const canon = Buffer.alloc(raw.length);
    let n = 0, inWord = false;
    for (const c0 of raw) {
      if (ASCII_WS.has(c0)) { inWord = false; continue; }
      if (!inWord && n > 0) canon[n++] = 0x20;
      inWord = true;
      canon[n++] = (c0 >= 0x41 && c0 <= 0x5a) ? c0 + 32 : c0;
    }
    const a = Buffer.from(canon.subarray(0, n)); canon.fill(0);
    const v = Buffer.from(raw);
    if (a.equals(v)) { v.fill(0); return [a]; }
    return [a, v];
  }
  // Non-ASCII: needs Unicode normalisation; JS strings cannot be wiped (documented).
  const s = raw.toString('utf8');
  const canonStr = s.toLowerCase().split(/\p{White_Space}+/u).filter(Boolean).join(' ').normalize('NFC');
  const a = Buffer.from(canonStr, 'utf8');
  const v = Buffer.from(s.normalize('NFC'), 'utf8');
  if (a.equals(v)) { v.fill(0); return [a]; }
  return [a, v];
}

function countWords(raw) {
  let n = 0, inWord = false;
  const s = isAscii(raw) ? null : raw.toString('utf8');
  if (s) return s.split(/\p{White_Space}+/u).filter(Boolean).length;
  for (const c of raw) { if (ASCII_WS.has(c)) inWord = false; else { if (!inWord) n++; inWord = true; } }
  return n;
}

// ---------------------------------------------------------------- open
function tryOpen(env, pass) {
  const key = crypto.scryptSync(pass, env.salt, 32, { N: env.N, r: env.r, p: env.p, maxmem: MAX_SCRYPT_MEM + 32 * 1024 * 1024 });
  const d = crypto.createDecipheriv('aes-256-gcm', key, env.nonce, { authTagLength: 16 });
  if (env.version >= 2) d.setAAD(env.header);
  d.setAuthTag(env.tag);
  let a = null, b = null;
  try {
    a = d.update(env.ct);
    b = d.final();                 // throws on tag mismatch
    const seed = Buffer.concat([a, b]);
    if (seed.length !== 32) { seed.fill(0); return null; }
    return seed;
  } catch (_) {
    return null;                   // wrong words OR a tampered sealed copy: one answer, no oracle
  } finally {
    key.fill(0);
    if (a) a.fill(0);
    if (b) b.fill(0);
  }
}

// Returns the 32-byte seed or throws Fail(WRONG_WORDS).
function openBlob(blobBytes, rawWords) {
  const env = parseBlob(blobBytes);
  const cands = passphraseCandidates(rawWords);
  try {
    for (const c of cands) {
      const seed = tryOpen(env, c);
      if (seed) return seed;
    }
  } finally {
    for (const c of cands) c.fill(0);
  }
  throw new Fail(EXIT.WRONG_WORDS, 'These words do not open this sealed copy. Check each word and that this is the newest kit. Nothing was written.');
}

// ---------------------------------------------------------------- keys
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');

function publicKeyFromSeed(seed) {
  const der = Buffer.concat([PKCS8_ED25519, seed]);
  try {
    const priv = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
    return Buffer.from(spki.subarray(spki.length - 32));
  } finally {
    der.fill(0);
  }
}

const B58 = Buffer.from('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz', 'ascii');

// Base58 into a Buffer (wipeable). Used for the public key and the optional wallet export.
function base58(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = new Uint8Array(bytes.length * 2 + 1);
  let len = 0;
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < len; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
    while (carry) { digits[len++] = carry % 58; carry = (carry / 58) | 0; }
  }
  const out = Buffer.alloc(zeros + len);
  for (let i = 0; i < zeros; i++) out[i] = B58[0];
  for (let i = 0; i < len; i++) out[zeros + i] = B58[digits[len - 1 - i]];
  digits.fill(0);
  return out;
}

// Solana CLI keypair JSON ("[n,n,...]") built as a Buffer so it can be wiped.
function keypairJson(secret64) {
  // Digits are written arithmetically: no secret byte ever becomes a JS string.
  const out = Buffer.alloc(2 + secret64.length * 4 + 1);
  let n = 0;
  out[n++] = 0x5b;                                   // [
  for (let i = 0; i < secret64.length; i++) {
    if (i) out[n++] = 0x2c;                          // ,
    const v = secret64[i];
    if (v >= 100) out[n++] = 0x30 + ((v / 100) | 0);
    if (v >= 10) out[n++] = 0x30 + (((v / 10) | 0) % 10);
    out[n++] = 0x30 + (v % 10);
  }
  out[n++] = 0x5d;                                   // ]
  out[n++] = 0x0a;
  const res = Buffer.from(out.subarray(0, n));
  out.fill(0);
  return res;
}

function writeSecretFile(path, data) {
  let fd;
  try {
    fd = fs.openSync(path, 'wx', 0o600);     // never overwrite; created owner-only
  } catch (e) {
    if (e.code === 'EEXIST') throw new Fail(EXIT.OUTPUT, 'Output file ' + path + ' already exists. Choose another --out path or move the old file.');
    throw new Fail(EXIT.OUTPUT, 'Cannot create ' + path + ': ' + e.code);
  }
  try {
    fs.fchmodSync(fd, 0o600);                 // umask-proof
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// ---------------------------------------------------------------- input
function readAllStdin() {
  const chunks = [];
  const b = Buffer.alloc(65536);
  for (;;) {
    let n;
    try { n = fs.readSync(0, b, 0, b.length, null); } catch (e) { if (e.code === 'EAGAIN') continue; if (e.code === 'EOF') break; throw e; }
    if (n === 0) break;
    chunks.push(Buffer.from(b.subarray(0, n)));
  }
  b.fill(0);
  const out = Buffer.concat(chunks);
  for (const c of chunks) c.fill(0);
  return out;
}

// Read one line of words with NO echo from the controlling terminal. Bytes only.
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const tty = require('tty');   // local terminal only (a tty.ReadStream wraps a file descriptor)
    let input = process.stdin;
    let ownFd = null;
    if (!input.isTTY) {
      try { ownFd = fs.openSync('/dev/tty', 'r'); } catch (_) {
        reject(new Fail(EXIT.USAGE, 'No terminal to read the words from. Run keeps-recover in a terminal window.'));
        return;
      }
      input = new tty.ReadStream(ownFd);
    }
    process.stderr.write(question);
    const buf = Buffer.alloc(1024);
    let n = 0;
    let esc = 0;                                  // 0 none, 1 after ESC, 2 inside CSI/SS3
    input.setRawMode(true);
    input.resume();
    const done = (err) => {
      input.removeListener('data', onData);
      try { input.setRawMode(false); } catch (_) { /* ignore */ }
      input.pause();
      if (ownFd !== null) input.destroy();
      process.stderr.write('\n');
      if (err) { buf.fill(0); reject(err); return; }
      const out = Buffer.from(buf.subarray(0, n));
      buf.fill(0);
      resolve(out);
    };
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === 0x0d || c === 0x0a) { chunk.fill(0); done(null); return; }
        if (c === 0x03 || c === 0x04) { chunk.fill(0); done(new Fail(EXIT.USAGE, 'Cancelled.')); return; }
        if (c === 0x7f || c === 0x08) { if (n > 0) buf[--n] = 0; continue; }
        if (c === 0x15) { buf.fill(0); n = 0; continue; }          // Ctrl-U clears the line
        // Arrow/function keys send ESC [ ... final-byte (or ESC O x): drop the whole sequence.
        if (esc === 1) { esc = (c === 0x5b || c === 0x4f) ? 2 : 0; continue; }
        if (esc === 2) { if (c >= 0x40 && c <= 0x7e) esc = 0; continue; }
        if (c === 0x1b) { esc = 1; continue; }
        if (c < 0x20 && c !== 0x09) continue;                       // other control bytes
        if (n >= buf.length) { chunk.fill(0); done(new Fail(EXIT.USAGE, 'That is too long for a recovery phrase (over ' + buf.length + ' characters). Nothing was opened.')); return; }
        buf[n++] = c;
      }
      chunk.fill(0);
    };
    input.on('data', onData);
  });
}

// ---------------------------------------------------------------- CLI
const USAGE = `keeps-recover ${VERSION}: open the sealed copy of Key C from your Keeps recovery kit, offline.

${RULE}

Usage:
  node keeps-recover.js --blob-file kit-blob.txt [--out key-c.json] [--expect <Key C>]
  zbarimg -q --raw kit-qr.png | node keeps-recover.js --blob-stdin [...]
  node keeps-recover.js            (paste the sealed copy when asked)

Options:
  --blob-file PATH     text file holding the sealed copy (the text under the QR code)
  --blob-stdin         read the sealed copy from standard input
  --out PATH           where to write the Solana keypair file (default: key-c.json).
                       Created with mode 600; never overwrites an existing file.
  --expect PUBKEY      the "Key C" address printed on your kit. If the opened key does
                       not match, nothing is written.
  --base58-out PATH    also write the 64-byte secret key in base58 (wallet "import
                       private key" format), mode 600.
  --words-stdin        read the words from standard input instead of the terminal
                       (for scripted tests; the blob must then come from --blob-file)
  --version, --help

The words are asked for at a prompt and never shown, logged or stored.
Exit codes: 0 ok, 1 wrong words, 2 usage, 3 network setting present, 4 bad sealed copy,
5 key does not match --expect, 6 output file problem.
`;

function parseArgs(argv) {
  const o = { out: 'key-c.json' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Fail(EXIT.USAGE, a + ' needs a value.'); return argv[++i]; };
    switch (a) {
      case '--blob-file': o.blobFile = val(); break;
      case '--blob-stdin': o.blobStdin = true; break;
      case '--out': o.out = val(); break;
      case '--expect': o.expect = val(); break;
      case '--base58-out': o.base58Out = val(); break;
      case '--words-stdin': o.wordsStdin = true; break;
      case '--help': case '-h': o.help = true; break;
      case '--version': o.version = true; break;
      default: throw new Fail(EXIT.USAGE, 'Unknown argument "' + a.split('=')[0] + '". See --help.');
    }
  }
  if (o.blobStdin && o.wordsStdin) throw new Fail(EXIT.USAGE, '--blob-stdin and --words-stdin cannot both use standard input.');
  return o;
}

function looksLikeImage(b) {
  return (b.length > 4 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) ||   // PNG
         (b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) ||                     // JPEG
         (b.length > 4 && b.subarray(0, 4).toString('latin1') === '%PDF');
}

const wrote = [];   // files created so far, for an honest message on an unexpected error

async function main(argv) {
  const why = refuseNetwork(argv, process.env, process.execArgv);
  if (why.length) {
    throw new Fail(EXIT.NETWORK, 'keeps-recover runs offline only and refuses to start with network settings present:\n  - ' +
      why.join('\n  - ') + '\nRemove them (for example: env -i PATH="$PATH" HOME="$HOME" node keeps-recover.js ...) and run again with Wi-Fi off.');
  }
  const o = parseArgs(argv);
  if (o.help) { process.stdout.write(USAGE); return EXIT.OK; }
  if (o.version) { process.stdout.write('keeps-recover ' + VERSION + '\n'); return EXIT.OK; }

  process.stderr.write('keeps-recover ' + VERSION + ' (offline)\n' + RULE + '\n\n');

  let blobText;
  if (o.blobFile) {
    let raw;
    try { raw = fs.readFileSync(o.blobFile); } catch (e) { throw new Fail(EXIT.USAGE, 'Cannot read ' + o.blobFile + ': ' + e.code); }
    if (looksLikeImage(raw)) throw new Fail(EXIT.USAGE, 'That file is an image or PDF. Decode the QR first (for example: zbarimg -q --raw kit-qr.png > kit-blob.txt) or type the text under the QR into a file.');
    blobText = raw.toString('utf8');
  } else if (o.blobStdin) {
    blobText = readAllStdin().toString('utf8');
  } else if (o.wordsStdin) {
    throw new Fail(EXIT.USAGE, '--words-stdin needs --blob-file.');
  } else {
    if (!process.stdin.isTTY) throw new Fail(EXIT.USAGE, 'Give the sealed copy with --blob-file or --blob-stdin.');
    process.stderr.write('Paste the sealed copy (the text under the QR code on your kit), then press Enter twice:\n');
    blobText = readPastedBlob();
  }
  const blob = decodeBlobText(blobText);
  const env = parseBlob(blob);      // fail fast on format before asking for the words
  process.stderr.write('Sealed copy OK (format v' + env.version + ', scrypt N=2^' + env.log2N + ' r=' + env.r + ' p=' + env.p + ').\n');

  let words;
  if (o.wordsStdin) {
    words = readAllStdin();
    let end = words.length;           // drop one trailing newline (pipe convenience)
    if (end && words[end - 1] === 0x0a) end--;
    if (end && words[end - 1] === 0x0d) end--;
    const w = Buffer.from(words.subarray(0, end)); words.fill(0); words = w;
  } else {
    words = await promptHidden('Type your six recovery words (nothing will show), then press Enter: ');
  }
  let seed = null, pub = null, secret = null, json = null, b58secret = null;
  try {
    if (words.length === 0) throw new Fail(EXIT.USAGE, 'No words entered.');
    const wc = countWords(words);
    if (wc !== 6) process.stderr.write('Note: that is not six words. Trying anyway (older Keeps may use a different passphrase).\n');
    process.stderr.write('Opening (this takes a few seconds)...\n');
    seed = openBlob(blob, words);
    pub = publicKeyFromSeed(seed);
    const pubB58 = base58(pub).toString('ascii');
    if (o.expect !== undefined && o.expect.trim() !== pubB58) {
      throw new Fail(EXIT.MISMATCH, 'The opened key is ' + pubB58 + ' but --expect was ' + o.expect.trim() + '.\nThis sealed copy is not the Key C you expected (an old kit, or another Keep). Nothing was written.');
    }
    secret = Buffer.concat([seed, pub]);
    json = keypairJson(secret);
    writeSecretFile(o.out, json);
    wrote.push(o.out);
    if (o.base58Out) {
      b58secret = base58(secret);
      const line = Buffer.concat([b58secret, Buffer.from('\n')]);
      try { writeSecretFile(o.base58Out, line); wrote.push(o.base58Out); } finally { line.fill(0); }
    }
    process.stdout.write('Key C public key: ' + pubB58 + '\n');
    process.stderr.write('\nCheck that this matches the "Key C" line on your kit.\n' +
      'Wrote the Solana keypair file ' + o.out + ' (owner-only, mode 600).' +
      (o.base58Out ? '\nWrote the base58 secret key ' + o.base58Out + ' (owner-only, mode 600).' : '') +
      '\nThis file IS your recovery key. Keep it offline and delete it once your money has moved.\n');
    return EXIT.OK;
  } finally {
    words.fill(0);
    for (const b of [seed, pub, secret, json, b58secret]) if (b) b.fill(0);
  }
}

// The sealed copy is ciphertext, so it may be echoed. Reads lines until a blank line.
function readPastedBlob() {
  const b = Buffer.alloc(4096);
  let text = '';
  for (;;) {
    let n;
    try { n = fs.readSync(0, b, 0, b.length, null); } catch (e) { if (e.code === 'EAGAIN') continue; throw e; }
    if (n === 0) break;
    const s = b.subarray(0, n).toString('utf8');
    if (s.trim() === '' && text.trim() !== '') break;
    text += s;
  }
  return text;
}

module.exports = {
  VERSION, RULE, EXIT, Fail,
  refuseNetwork, decodeBlobText, parseBlob, passphraseCandidates, openBlob,
  publicKeyFromSeed, base58, keypairJson, writeSecretFile,
};

if (require.main === module) {
  process.stdout.on('error', () => { /* closed pipe: the result is still in the file; never crash with data */ });
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (e) => {
      if (e instanceof Fail) { process.stderr.write('\nkeeps-recover: ' + e.message + '\n'); process.exitCode = e.code; return; }
      // Unexpected: print only the type, never data that could include input.
      process.stderr.write('\nkeeps-recover: unexpected error (' + (e && e.name) + '). ' +
        (wrote.length ? 'Already written: ' + wrote.join(', ') + ' (mode 600). Check it, or delete it.' : 'Nothing was written.') + '\n');
      process.exitCode = 70;
    });
}
