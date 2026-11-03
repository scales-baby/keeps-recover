// Static check of the scales.baby/recover page.
//   - no <form>, <input>, <textarea>, <select>, <button>, contenteditable, <script>, <iframe>,
//     <object>, <embed>, event-handler attributes, javascript: URLs, wallet-connect code;
//   - no link to a reveal screen or any deep link into the app;
//   - no clickable links at all except https://github.com/scales-baby/keeps-recover/releases...;
//   - carries "We never ask for your words" and the rule sentence;
//   - the published hash equals SHA256SUMS and the tool's VERSION.
'use strict';
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const RULE = 'Only type your words into the Keeps app or the offline recovery tool. Never into a website.';
const file = process.argv[2] || path.join(root, 'site', 'recover.html');
const html = fs.readFileSync(file, 'utf8');
const lower = html.toLowerCase();
const fail = [];

const banned = [
  [/<form\b/, '<form>'], [/<input\b/, '<input>'], [/<textarea\b/, '<textarea>'], [/<select\b/, '<select>'],
  [/<button\b/, '<button>'], [/contenteditable/, 'contenteditable'], [/<script\b/, '<script>'],
  [/<iframe\b/, '<iframe>'], [/<object\b/, '<object>'], [/<embed\b/, '<embed>'], [/<link\b/, '<link> (external resources)'],
  [/<img\b/, '<img>'], [/\son[a-z]+\s*=/, 'event-handler attribute'], [/javascript:/, 'javascript: URL'],
  [/walletconnect|wallet-adapter|window\.solana|phantom\.app\/ul|solflare\.com\/ul|connect wallet/, 'wallet connect'],
  [/keeps:\/\/|scales:\/\/|reveal-?(recovery|phone)|\/reveal\b|settings\/advanced/, 'link to a reveal screen / app deep link'],
  [/<meta[^>]+http-equiv=["']?refresh/, 'meta refresh'],
  [/formaction\s*=|srcset\s*=|\sping\s*=|<source\b|<video\b|<audio\b|<base\b|<area\b|<svg\b|<math\b|<dialog\b|<details\b/, 'active or resource-loading markup'],
];
for (const [re, what] of banned) if (re.test(lower)) fail.push('contains ' + what);

const hrefs = [...html.matchAll(/\b(?:href|src|action)\s*=\s*["']?([^"'\s>]+)/gi)].map((m) => m[1]);
for (const h of hrefs) {
  if (!/^https:\/\/github\.com\/scales-baby\/keeps-recover\/releases(\/[A-Za-z0-9._\/-]*)?$/.test(h)) fail.push('link not allowed: ' + h);
}
if (!html.includes(RULE)) fail.push('missing the rule sentence');
if (!/we never ask for your words/i.test(html)) fail.push('missing "We never ask for your words"');

const sums = fs.readFileSync(path.join(root, 'SHA256SUMS'), 'utf8').match(/^([0-9a-f]{64})\s+\*?keeps-recover\.js$/m);
// Release table: the NEWEST row (first) must be the tool's VERSION with the SHA256SUMS hash.
const rows = [...html.matchAll(/<tr data-version="([^"]+)"><td>([^<]+)<\/td><td><code>([0-9a-f]{64})<\/code><\/td>/g)];
const ver = fs.readFileSync(path.join(root, 'keeps-recover.js'), 'utf8').match(/const VERSION = '([^']+)'/);
if (!rows.length) fail.push('no release table rows');
else {
  const [, v, vText, h] = rows[0];
  if (!ver || v !== ver[1] || vText !== v) fail.push('newest release row is not the tool VERSION');
  if (!sums || h !== sums[1]) fail.push('newest release hash does not match SHA256SUMS (run node scripts/stamp-page.js)');
  if (new Set(rows.map((r) => r[1])).size !== rows.length) fail.push('duplicate version rows');
}

if (fail.length) { console.error('check-page FAILED for ' + file + ':\n  - ' + fail.join('\n  - ')); process.exit(1); }
console.log('check-page OK: ' + file);
