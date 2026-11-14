# keeps-recover

**Only type your words into the Keeps app or the offline recovery tool. Never into a website.**

`keeps-recover` opens the sealed copy of **Key C** printed on your Keeps recovery kit, on your own computer, with the network off. You give it the sealed copy (the text under the QR code) and your six recovery words. It gives you Key C as a Solana keypair file and prints Key C's public key so you can check it against the "Key C" line on your kit.

It is one file, `keeps-recover.js`, about 450 lines of JavaScript that uses only the Node.js standard library (`crypto`, `fs`, `tty`). There is nothing to install besides Node.js and nothing it downloads.

## Threat model

What it protects against:

- **Phishing.** Keeps, scales.baby and no website will ever ask for your six words. A page that asks for them is an attack. Only type your words into the Keeps app or this offline tool. Never into a website. That is why there is no web version of this tool, why scales.baby/recover has no input fields, and why this tool refuses to run with network settings present.
- **A dead company.** The kit plus your words plus this tool give you Key C with no Keeps app, no Keeps server and no Keeps company. With Key A (from the app) you hold 2 of the 3 keys of your Keep and can move the money with the public Squads tools. If Keeps' sign-in has stopped, getting Key A out of the app takes at least 10 days, counted from your first try in the app (see "Move your money without Keeps", step 2).
- **A stolen kit.** The sealed copy is AES-256-GCM ciphertext under a key derived from your six words with scrypt (N=2^17, r=8, p=1, about 128 MB of memory per guess). Six words from the 7,776-word EFF list are 77.5 bits; nobody can guess them from the kit. That is also why the kit and the words must never be stored together.
- **Leaks from the tool itself.** It has no network code: it never loads `net`, `http`, `https`, `http2`, `dns`, `tls`, `dgram`, `child_process` or `worker_threads`, never calls `fetch`, and exits with code 3 before reading anything if a proxy or RPC-like environment variable, `NODE_OPTIONS`, any Node runtime option (such as `--inspect` or `--require`) or a network-like flag is present. The tests prove both by grep and at runtime (every Node network entry point is trapped during a full recovery and none is touched). It never prints or logs the words, the seed or the secret key. It writes the keypair file with mode 600 and never overwrites an existing file.
- **Wrong words.** A wrong word fails the GCM authentication tag and you get one generic answer: "These words do not open this sealed copy." A tampered sealed copy gives exactly the same answer. Nothing is written.

What it does not protect against:

- **A compromised computer.** Malware on the computer you type into can read your words. Use a computer you trust, ideally one that has been offline for this, and turn Wi-Fi off before you start.
- **A tampered copy of this tool.** Check the SHA-256 (below) against scales.baby/recover and the GitHub release before you run it.
- **Memory hygiene limits.** The tool wipes the buffers it controls (the words, the derived key, the seed, the secret key and the file contents) as soon as it is done with them. JavaScript cannot wipe what Node keeps internally (OpenSSL's copies, the Ed25519 key object), nor strings: words made only of plain ASCII letters (all six-word kits) are never turned into strings, but a passphrase with non-ASCII characters has to be, for Unicode normalisation. The process exits right after, which frees all of it.
- **The keypair file itself.** It IS your recovery key. Keep it on the offline computer, use it, then delete it.

## Verify before you run

The SHA-256 of each release is published in three places that must agree: this repository's `SHA256SUMS`, the GitHub release page, and the release table on scales.baby/recover. Your printed kit carries the hash of the version that was current when you printed it; the table keeps every version, and old releases are never deleted, so an older kit still matches its own version.

```
shasum -a 256 keeps-recover.js        # macOS
sha256sum keeps-recover.js            # Linux
Get-FileHash keeps-recover.js         # Windows PowerShell (prints capitals; case does not matter)
```

If the hash does not match all of them, do not run the file.

To rebuild from source and check the hash yourself: `sh scripts/build.sh` copies the file into `dist/` byte for byte and writes `dist/SHA256SUMS`; it must equal the committed `SHA256SUMS`. CI does this twice, on Linux and macOS, and fails on any difference.

## Use it

You need: Node.js 20 or newer, the kit, your six words, a computer with the network off.

1. Copy `keeps-recover.js` to the offline computer and check its hash (above).
2. Put the sealed copy into a text file. Either type the text under the QR code on your kit into `kit-blob.txt` (spaces and line breaks do not matter; the leading `KCRN2:` label is optional), or decode the QR with an offline scanner such as `zbarimg` (installed before you go offline): `zbarimg -q --raw kit-qr.png > kit-blob.txt`.
3. Turn Wi-Fi off. Run, with a clean environment so no network setting leaks in:

   ```
   env -i PATH="$PATH" HOME="$HOME" node keeps-recover.js --blob-file kit-blob.txt --expect <Key C from your kit>
   ```

4. Type your six words at the prompt. Nothing is shown while you type. Case and extra spaces do not matter.
5. It prints `Key C public key: ...` and writes `key-c.json` (mode 600 on macOS and Linux). With `--expect`, it only writes the file if the key matches your kit. Without it, compare the printed key with the "Key C" line yourself.

Windows: there is no `env -i`; open a new PowerShell window and run `node keeps-recover.js --blob-file kit-blob.txt ...` (the tool still refuses if a proxy or `NODE_OPTIONS` is set). Use `--blob-file`, not `--blob-stdin`. File mode 600 does not apply on Windows: keep the file in your own user folder and delete it after use.

Options: `--out PATH` (default `key-c.json`), `--base58-out PATH` (the 64-byte secret key in base58, the "import private key" format of Phantom, Solflare and Backpack; also mode 600), `--blob-stdin` (read the sealed copy from a pipe, e.g. `zbarimg -q --raw kit-qr.png | node keeps-recover.js --blob-stdin`; the words are then read from the terminal). Exit codes: 0 ok, 1 wrong words, 2 usage, 3 network setting present, 4 bad sealed copy, 5 key does not match `--expect`, 6 output file problem.

## Move your money without Keeps

Your Keep is a Squads v4 multisig, 2 of 3: Key A (your phone), Key B (the Keeps service key), Key C (your recovery key). Any two keys can move the money. These steps match the six exit steps on your kit.

1. **Key C:** this tool (above), or Keeps app > Settings > Advanced > Reveal recovery key.
2. **Key A:** Keeps app > Settings > Advanced > Reveal phone key. The two reveals are 24 hours apart on purpose. Revealing Key A normally needs your Keeps sign-in. **If Keeps' sign-in has stopped, it takes at least 10 days from your first try:**
   - Open Reveal phone key as soon as sign-in fails. The 7 days count from that first try on this phone, not from when Keeps stopped.
   - Keep the phone switched on. Time with it switched off does not count. If Keeps' sign-in answers again, the count starts over.
   - After 7 days, open Reveal phone key again and type your six words in the app.
   - The app then waits 72 hours more before it shows Key A. Reveal it within the 72 hours after that, or the wait lapses.
   - Freezing your Keep cancels the wait.
   - A Ledger or "other wallet" recovery key is not affected: its reveal needs only your phone.
3. **Load the keys.** For the Squads CLI keep them as keypair files (`key-c.json`, and Key A saved the same way). For a wallet, import each with `--base58-out` / the app's export into Phantom, Solflare or Backpack. Importing into a wallet puts the key on an online device: do it only when you are ready to move the money.
4. **Open a Squads tool** with the Multisig address from your kit. The program is `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`.
   - The Squads public UI: <https://github.com/Squads-Protocol/squads-v4-public-ui> (run it yourself; connect the wallet holding Key A, then the one holding Key C).
   - The Squads CLI: `cargo install squads-multisig-cli` (from <https://github.com/Squads-Protocol/v4>).
5. **Transfer from Vault 0** to your destination: create the transfer, approve with Key A, approve with Key C, execute. Repeat per token. The wallet you send a token to must already hold that token once (or use the UI, which creates the token account). The public UI is the simple route here: the CLI's `vault-transaction-create` takes a pre-built, serialized transaction message.
6. **Optional: take Key B out**, so the Keep is yours with no Keeps anywhere. With the CLI (the transaction index comes from the create step's output):

   ```
   squads-multisig-cli config-transaction-create --rpc-url <RPC> --keypair key-a.json \
       --multisig-pubkey <Multisig from kit> --action "AddMember <a key you hold> 7"
   squads-multisig-cli proposal-vote --rpc-url <RPC> --keypair key-a.json \
       --multisig-pubkey <Multisig> --transaction-index <N> --action Approve
   squads-multisig-cli proposal-vote --rpc-url <RPC> --keypair key-c.json \
       --multisig-pubkey <Multisig> --transaction-index <N> --action Approve
   squads-multisig-cli config-transaction-execute --rpc-url <RPC> --keypair key-a.json \
       --multisig-pubkey <Multisig> --transaction-index <N>
   ```

   Then the same four commands with `--action "RemoveMember <Key B from kit>"`. Keep the threshold at 2.

These later steps are online by nature (they send transactions). Do them after `keeps-recover` has finished, and only with the keypair files, never with the words. The words are needed for one thing only: step 1, offline.

## The sealed copy format

The kit prints the sealed copy as `KCRN2:` followed by standard base64 of the blob (base64url is also accepted). The blob is version 2 (version 1 also opens):

```
[0..4)   "KCRN"
[4]      version = 2 (1 = legacy, no AAD)
[5]      kdf = 1 (scrypt)
[6]      log2N (17)
[7..11)  r, little-endian u32 (8)
[11..15) p, little-endian u32 (1)
[15]     salt length = 16
[16..32) salt
[32..92) AES-256-GCM: nonce (12) || ciphertext (32) || tag (16)
key = scrypt(NFC(passphrase), salt, N = 2^log2N, r, p, 32 bytes); AAD = bytes [0..32) for v2
plaintext = the 32-byte Ed25519 seed of Key C
```

Passphrase: the six words, lowercase, one space between. A free-form passphrase from older Keeps is used exactly as typed (NFC), the way the app does it. The tool tries the lowercased, space-collapsed form first and the exact form second, so it opens everything the app opens; it is slightly more tolerant than the app (a free-form passphrase typed with different case or spacing also opens), which costs nothing because an attacker never needs this tool to guess. Header fields are bounded before any work (log2N 10..20, r 1..32, p 1..16, at most 256 MB), as in the app.

Output: the Solana CLI keypair format, a JSON array of the 64 bytes seed || public key, the same keypair the app exports.

## Tests

`node --test test/keeps-recover.test.js` and `node scripts/check-page.js`. The test vectors in `test/fixtures/vectors.json` are synthetic: the seeds are byte patterns and the passphrases are public test phrases. They were sealed by the Keeps app's own code, and each public key was cross-checked with `solana-keygen pubkey`.

## License

Apache-2.0, see [LICENSE](LICENSE). To report a security issue, see [SECURITY.md](SECURITY.md).
