'use strict';
// Run: node --test test/
// Every passphrase and seed below is a synthetic, public test value (seeds are
// arithmetic byte patterns). Fixtures were sealed by the Keeps app's own sealing
// code and cross-checked with solana-keygen.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const TOOL = path.join(ROOT, 'keeps-recover.js');
const R = require(TOOL);
const VECTORS = require('./fixtures/vectors.json');
const RULE = 'Only type your words into the Keeps app or the offline recovery tool. Never into a website.';

// Base58 public keys, cross-checked with `solana-keygen pubkey` on the tool's output files
// and equal to the CryptoKit-derived publicKeyHex in the fixtures (asserted below).
const EXPECTED_B58 = {
  'v2-prod-six-words': '6BoT7babwa3tgn3sqeqrGumRpvyYX1gt5PkQ57D1MUAw',
  'v2-low-cost': '6BoT7babwa3tgn3sqeqrGumRpvyYX1gt5PkQ57D1MUAw',
  'v2-freeform-verbatim': 'FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF',
  'v2-nfc': '5rXezEUcPoLLDKATEsDJzUdNojasqE2ekkHntNLfEQtL',
  'v1-legacy': 'BNwDw5bJYr1kU5Kthi3cthWXKfnTFJ6ZKgfc6y1rTLXg',
};

const vec = (name) => VECTORS.find((v) => v.name === name);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kr-'));
const CLEAN_ENV = { PATH: process.env.PATH, HOME: os.tmpdir() };

function writeBlob(dir, v, opts = {}) {
  let b = Buffer.from(v.blobBase64, 'base64');
  if (opts.mutate) { b = Buffer.from(b); opts.mutate(b); }
  const text = opts.raw ? b.toString('base64') : 'KCRN' + v.version + ':\n' + b.toString('base64').replace(/(.{40})/g, '$1\n');
  const p = path.join(dir, 'blob.txt');
  fs.writeFileSync(p, text);
  return p;
}

function run(args, { words = '', env = CLEAN_ENV, execArgv = [], cwd, detached = false } = {}) {
  const r = spawnSync(process.execPath, [...execArgv, TOOL, ...args], { input: words, env, cwd, encoding: 'utf8', detached, timeout: 60000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

function assertNoSecrets(text, v) {
  text = text.split(os.tmpdir()).join('<tmp>');   // file paths are not output we judge
  assert.ok(!text.includes(v.passphraseTyped), 'passphrase leaked');
  const seed = Buffer.from(v.seedHex, 'hex');
  const secret = Buffer.concat([seed, Buffer.from(v.publicKeyHex, 'hex')]);
  for (const w of v.passphraseTyped.split(/\s+/)) {
    const re = new RegExp('(^|[^A-Za-z])' + w.replace(/[^A-Za-z0-9]/g, '\\$&') + '($|[^A-Za-z])');
    if (w.length > 2) assert.ok(!re.test(text), 'a word leaked');
  }
  assert.ok(!text.includes(v.seedHex), 'seed hex leaked');
  assert.ok(!text.includes(R.base58(seed).toString()), 'seed b58 leaked');
  assert.ok(!text.includes(R.base58(secret).toString()), 'secret b58 leaked');
  assert.ok(!text.includes(JSON.stringify([...secret])), 'keypair json leaked');
}

// ------------------------------------------------------------------ vectors
for (const v of VECTORS) {
  test(`vector ${v.name}: opens the app-sealed vector and prints the matching public key`, () => {
    const d = tmp();
    const out = path.join(d, 'key-c.json');
    const r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', out], { words: v.passphraseTyped + '\n' });
    assert.equal(r.code, 0, r.err);
    assert.equal(r.out, 'Key C public key: ' + EXPECTED_B58[v.name] + '\n');
    assert.equal(fs.statSync(out).mode & 0o777, 0o600);
    const kp = Buffer.from(JSON.parse(fs.readFileSync(out, 'utf8')));
    assert.equal(kp.subarray(0, 32).toString('hex'), v.seedHex);
    assert.equal(kp.subarray(32).toString('hex'), v.publicKeyHex);      // CryptoKit-derived
    assert.equal(R.base58(Buffer.from(v.publicKeyHex, 'hex')).toString(), EXPECTED_B58[v.name]);
    assertNoSecrets(r.out + r.err, v);
    assert.ok(r.err.includes(RULE));
  });
}

test('production vector is the real cost (N=2^17, r=8, p=1) and v2', () => {
  const v = vec('v2-prod-six-words');
  const env = R.parseBlob(Buffer.from(v.blobBase64, 'base64'));
  assert.deepEqual([env.version, env.log2N, env.r, env.p], [2, 17, 8, 1]);
});

test('six words typed with odd case and spacing open like the app (canonical six-word form)', () => {
  const v = vec('v2-prod-six-words');
  const d = tmp();
  const r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', path.join(d, 'k.json')],
    { words: '  Ranch UNSHAKEN trombone \t cramp  acetone Banister \r\n' });
  assert.equal(r.code, 0, r.err);
  assert.equal(r.out, 'Key C public key: ' + EXPECTED_B58[v.name] + '\n');
});

test('canonical form matches the app canonical-form vectors', () => {
  const c = R.passphraseCandidates(Buffer.from('  Abacus  ZOOM t-shirt yo-yo Felt-Tip abdomen'));
  assert.equal(c[0].toString(), 'abacus zoom t-shirt yo-yo felt-tip abdomen');
  const c2 = R.passphraseCandidates(Buffer.from('ranch unshaken trombone cramp acetone banister'));
  assert.equal(c2.length, 1);
  assert.equal(c2[0].toString(), 'ranch unshaken trombone cramp acetone banister');
});

test('blob text: bare base64, base64url and wrapped lines all decode', () => {
  const v = vec('v2-low-cost');
  const raw = Buffer.from(v.blobBase64, 'base64');
  assert.ok(R.decodeBlobText(v.blobBase64).equals(raw));
  assert.ok(R.decodeBlobText(raw.toString('base64url')).equals(raw));
  assert.ok(R.decodeBlobText('kcrn2:  ' + v.blobBase64.replace(/(.{10})/g, '$1\n ')).equals(raw));
});

// ------------------------------------------------------------------ wrong words / no oracle
test('wrong words: exit 1, one generic message, nothing written, words not echoed', () => {
  const v = vec('v2-low-cost');
  const d = tmp();
  const out = path.join(d, 'k.json');
  const r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', out], { words: 'correct battery staple rivet' });
  assert.equal(r.code, 1);
  assert.ok(r.err.includes('These words do not open this sealed copy.'));
  assert.ok(!fs.existsSync(out));
  assert.ok(!r.err.includes('rivet') && !r.err.includes('staple'));
  assert.equal(r.out, '');
});

test('tampered header or ciphertext gives the SAME answer as wrong words (no oracle)', () => {
  const v = vec('v2-low-cost');
  const msgs = new Set();
  const cases = [
    null,                                   // wrong words (reference)
    (b) => { b[4] = 1; },                   // v2 -> v1 downgrade (AAD dropped)
    (b) => { b[20] ^= 1; },                 // salt bit
    (b) => { b[40] ^= 1; },                 // ciphertext bit
    (b) => { b[b.length - 1] ^= 1; },       // tag bit
  ];
  for (const m of cases) {
    const d = tmp();
    const r = run(['--blob-file', writeBlob(d, v, m ? { mutate: m } : {}), '--words-stdin', '--out', path.join(d, 'k.json')],
      { words: m ? v.passphraseTyped : 'correct battery staple rivet' });
    assert.equal(r.code, 1, r.err);
    msgs.add(r.err.split('\n').filter((l) => l.startsWith('keeps-recover:')).join('\n'));
    assert.ok(!fs.existsSync(path.join(d, 'k.json')));
  }
  assert.equal(msgs.size, 1);
});

test('hostile or broken envelopes are refused before any KDF work (exit 4)', () => {
  const v = vec('v2-low-cost');
  const muts = [
    (b) => { b[6] = 30; },                                  // log2N out of range
    (b) => { b[6] = 21; },
    (b) => { b.writeUInt32LE(0xffffffff, 7); },             // r
    (b) => { b.writeUInt32LE(0xffffffff, 11); },            // p
    (b) => { b[15] = 15; },                                 // salt length
    (b) => { b[0] = 0x58; },                                // magic
    (b) => { b[5] = 2; },                                   // kdf id
    (b) => { b[4] = 3; },                                   // version
  ];
  for (const m of muts) {
    const b = Buffer.from(v.blobBase64, 'base64'); m(b);
    assert.throws(() => R.parseBlob(b), (e) => e.code === R.EXIT.BAD_BLOB);
  }
  const full = Buffer.from(v.blobBase64, 'base64');
  assert.throws(() => R.parseBlob(full.subarray(0, full.length - 1)), (e) => e.code === 4);
  assert.throws(() => R.parseBlob(Buffer.concat([full, Buffer.from([0])])), (e) => e.code === 4);
  // log2N=20 with r=32 exceeds the 256 MiB ceiling (same bound as the app).
  const big = Buffer.from(full); big[6] = 20; big.writeUInt32LE(32, 7);
  assert.throws(() => R.parseBlob(big), (e) => e.code === 4);
  const d = tmp();
  const r = run(['--blob-file', writeBlob(d, v, { mutate: (b) => { b[6] = 30; } }), '--words-stdin'], { words: 'x' });
  assert.equal(r.code, 4);
});

test('an image passed as the blob gets a clear hint (exit 2)', () => {
  const d = tmp();
  const p = path.join(d, 'qr.png');
  fs.writeFileSync(p, Buffer.from('89504e470d0a1a0a0000', 'hex'));
  const r = run(['--blob-file', p, '--words-stdin'], { words: 'x' });
  assert.equal(r.code, 2);
  assert.match(r.err, /zbarimg/);
});

// ------------------------------------------------------------------ output safety
test('--expect: mismatch writes nothing (exit 5); match succeeds', () => {
  const v = vec('v2-low-cost');
  const d = tmp();
  const out = path.join(d, 'k.json');
  let r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', out, '--expect', EXPECTED_B58['v1-legacy']], { words: v.passphraseTyped });
  assert.equal(r.code, 5);
  assert.ok(!fs.existsSync(out));
  r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', out, '--expect', EXPECTED_B58[v.name]], { words: v.passphraseTyped });
  assert.equal(r.code, 0, r.err);
});

test('never overwrites an existing file (exit 6); --base58-out is mode 600 and correct', () => {
  const v = vec('v2-low-cost');
  const d = tmp();
  const out = path.join(d, 'k.json');
  fs.writeFileSync(out, 'keep me');
  let r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', out], { words: v.passphraseTyped });
  assert.equal(r.code, 6);
  assert.equal(fs.readFileSync(out, 'utf8'), 'keep me');
  const out2 = path.join(d, 'k2.json');
  const b58 = path.join(d, 'k2.b58');
  r = run(['--blob-file', writeBlob(d, v), '--words-stdin', '--out', out2, '--base58-out', b58], { words: v.passphraseTyped });
  assert.equal(r.code, 0, r.err);
  assert.equal(fs.statSync(b58).mode & 0o777, 0o600);
  const secret = Buffer.concat([Buffer.from(v.seedHex, 'hex'), Buffer.from(v.publicKeyHex, 'hex')]);
  assert.equal(fs.readFileSync(b58, 'utf8').trim(), R.base58(secret).toString());
  assertNoSecrets(r.out + r.err, v);
});

test('--blob-stdin with no terminal for the words fails cleanly (exit 2), no file', () => {
  const v = vec('v2-low-cost');
  const d = tmp();
  const r = spawnSync(process.execPath, [TOOL, '--blob-stdin', '--out', path.join(d, 'k.json')],
    { input: v.blobBase64, env: CLEAN_ENV, encoding: 'utf8', detached: true, timeout: 30000 });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /Sealed copy OK/);
  assert.ok(!fs.existsSync(path.join(d, 'k.json')));
});

// ------------------------------------------------------------------ no network
test('no network, runtime: refuses network-ish env vars, flags and Node options (exit 3) before reading anything', () => {
  const v = vec('v2-low-cost');
  const d = tmp();
  const blob = writeBlob(d, v);
  const base = ['--blob-file', blob, '--words-stdin', '--out', path.join(d, 'k.json')];
  const envs = ['HTTP_PROXY', 'https_proxy', 'ALL_PROXY', 'NO_PROXY', 'NODE_OPTIONS', 'NODE_EXTRA_CA_CERTS',
    'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY', 'SOLANA_RPC_URL', 'RPC_URL', 'ANCHOR_PROVIDER_URL', 'SOME_RPC_ENDPOINT'];
  for (const e of envs) {
    const r = run(base, { words: v.passphraseTyped, env: { ...CLEAN_ENV, [e]: e === 'NODE_OPTIONS' ? '--no-warnings' : 'http://127.0.0.1:1' } });
    assert.equal(r.code, 3, e + ': ' + r.err);
    assert.ok(r.err.includes(e));
  }
  const flags = [['--rpc-url', 'x'], ['--url', 'x'], ['-u', 'm'], ['--network'], ['--proxy=x'], ['--cluster', 'mainnet'], ['https://api.mainnet-beta.solana.com']];
  for (const f of flags) {
    const r = run([...base, ...f], { words: v.passphraseTyped });
    assert.equal(r.code, 3, f.join(' ') + ': ' + r.err);
  }
  for (const xa of [['--expose-gc'], ['--require', path.join(__dirname, 'fixtures', 'empty-preload.js')], ['--inspect-port=0']]) {
    const r = run(base, { words: v.passphraseTyped, execArgv: xa });
    assert.equal(r.code, 3, xa.join(' ') + ': ' + r.err);
  }
  assert.ok(!fs.existsSync(path.join(d, 'k.json')));
});

test('no network, runtime: a full successful recovery makes zero network calls (all entry points trapped)', () => {
  const v = vec('v2-prod-six-words');
  const d = tmp();
  const report = path.join(d, 'report.json');
  const r = spawnSync(process.execPath, [path.join(__dirname, 'net-trap.js'), report, TOOL,
    '--blob-file', writeBlob(d, v), '--words-stdin', '--out', path.join(d, 'k.json')],
  { input: v.passphraseTyped, env: CLEAN_ENV, encoding: 'utf8', timeout: 60000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, 'Key C public key: ' + EXPECTED_B58[v.name] + '\n');
  const rep = JSON.parse(fs.readFileSync(report, 'utf8'));
  assert.deepEqual(rep.hits, []);
});

test('no network, static: the tool has no network code path (grep)', () => {
  const src = fs.readFileSync(TOOL, 'utf8');
  const code = src.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  const requires = [...code.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]).sort();
  assert.deepEqual([...new Set(requires)], ['crypto', 'fs', 'tty']);
  assert.equal((code.match(/\brequire\s*\(/g) || []).length, 3, 'exactly three require calls, all literal');
  assert.ok(!/\brequire\s*\(\s*[^'"\s]/.test(code), 'no computed require');
  assert.ok(!/\brequire\s*\[|\bmodule\.constructor|createRequire|globalThis\s*\[/.test(code), 'no indirect loaders');
  for (const bad of [/\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /\bimport\s*\(/, /process\.binding/, /internalBinding/,
    /\beval\s*\(/, /new\s+Function/, /child_process/, /worker_threads/, /\bhttps?:\/\//, /\bdgram\b/, /\bnode:(?!test)/]) {
    assert.ok(!bad.test(code), 'forbidden pattern ' + bad);
  }
});

// ------------------------------------------------------------------ primitives
test('scrypt matches RFC 7914 vectors (standard test vectors)', () => {
  assert.equal(crypto.scryptSync('', '', 64, { N: 16, r: 1, p: 1 }).toString('hex'),
    '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');
  assert.equal(crypto.scryptSync('password', 'NaCl', 64, { N: 1024, r: 8, p: 16 }).toString('hex'),
    'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640');
});

test('base58 and Ed25519 derivation (RFC 8032 test 1)', () => {
  assert.equal(R.base58(Buffer.alloc(32)).toString(), '11111111111111111111111111111111');
  assert.equal(R.base58(Buffer.from('0001', 'hex')).toString(), '12');
  const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
  assert.equal(R.publicKeyFromSeed(seed).toString('hex'), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
});

// ------------------------------------------------------------------ rule sentence
test('the rule sentence is in the tool output, the README and the page', () => {
  const r = run(['--help']);
  assert.equal(r.code, 0);
  assert.ok(r.out.includes(RULE));
  assert.ok(fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8').includes(RULE));
  assert.ok(fs.readFileSync(path.join(ROOT, 'site', 'recover.html'), 'utf8').includes(RULE));
});

// ------------------------------------------------------------------ page check
test('page check: the page passes the static check, and the check catches inputs, scripts, wallet connect and stray links', () => {
  const check = path.join(ROOT, 'scripts', 'check-page.js');
  const page = path.join(ROOT, 'site', 'recover.html');
  assert.equal(spawnSync(process.execPath, [check, page]).status, 0);
  const html = fs.readFileSync(page, 'utf8');
  const bad = [
    html.replace('</main>', '<form><input name="w"></form></main>'),
    html.replace('</main>', '<textarea></textarea></main>'),
    html.replace('</main>', '<script>1</script></main>'),
    html.replace('</main>', '<p>Connect wallet</p></main>'),
    html.replace('</main>', '<a href="https://example.com">x</a></main>'),
    html.replace('</main>', '<a href="keeps://settings/advanced/reveal">x</a></main>'),
    html.replace('</main>', '<div onclick="x()">x</div></main>'),
    html.replace(RULE, ''),
    html.replace(/(<tr data-version="[^"]+"><td>[^<]+<\/td><td><code>)[0-9a-f]/, '$1' + 'x'),
    html.replace('</main>', '<img srcset="https://example.com/a.png"></main>'),
  ];
  for (const b of bad) {
    const d = tmp(); const p = path.join(d, 'p.html'); fs.writeFileSync(p, b);
    assert.equal(spawnSync(process.execPath, [check, p]).status, 1);
  }
});

// ---------------------------------------------------------------- audit 2026-11 (SRV-10)
test('SRV-10: the README and the page describe the Key A wait as the 369 app runs it', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const page = fs.readFileSync(path.join(ROOT, 'site', 'recover.html'), 'utf8');
  for (const doc of [readme, page]) {
    assert.match(doc, /it takes at least 10 days from your first try/);
    assert.match(doc, /Open Reveal phone key as soon as sign-in fails/);
    assert.match(doc, /[Tt]he 7 days count from that first try on this phone, not from when Keeps stopped/);
    assert.match(doc, /[Tt]ime with it switched off does not count/);
    assert.match(doc, /After 7 days, open Reveal phone key again and type your six words in the app/);
    assert.match(doc, /waits 72 hours more before it shows Key A/);
    assert.ok(!/has been down for 7 days/.test(doc), 'the old wording (7 days from when Keeps went down) is gone');
  }
  assert.ok(!/No later step asks for them/.test(page), 'the page no longer says only step 1 needs the words');
});

test('SRV-10 review K-2/K-3: printed kits keep matching; the 1.0.0 row and hash stay', () => {
  const H100 = '53b450e4296b730165e92461430e1c7e1f5101c562cfdf17567aed619522a8d4';
  const page = fs.readFileSync(path.join(ROOT, 'site', 'recover.html'), 'utf8');
  assert.ok(page.includes(`<tr data-version="1.0.0"><td>1.0.0</td><td><code>${H100}</code></td><td>2026-11-03</td></tr>`),
    'the 1.0.0 row that 366 to 369 kits name is unchanged');
  assert.ok(!/not yet released/.test(page), 'no unreleased version is listed on the page');
});
