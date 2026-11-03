// Writes the hash from SHA256SUMS into the release table of site/recover.html for the tool's
// current VERSION: replaces that version's row, or adds a new row on top. Rows only grow.
//   node scripts/stamp-page.js [release-date]
'use strict';
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '..');
const sum = fs.readFileSync(path.join(root, 'SHA256SUMS'), 'utf8').match(/^([0-9a-f]{64})\s+\*?keeps-recover\.js$/m);
if (!sum) throw new Error('SHA256SUMS has no keeps-recover.js line');
const ver = fs.readFileSync(path.join(root, 'keeps-recover.js'), 'utf8').match(/const VERSION = '([^']+)'/)[1];
const date = process.argv[2] || 'not yet released';
const page = path.join(root, 'site', 'recover.html');
let html = fs.readFileSync(page, 'utf8');
const row = '<tr data-version="' + ver + '"><td>' + ver + '</td><td><code>' + sum[1] + '</code></td><td>' + date + '</td></tr>';
const re = new RegExp('<tr data-version="' + ver.replace(/\./g, '\\.') + '">.*?</tr>');
html = re.test(html) ? html.replace(re, row) : html.replace('<tbody>\n', '<tbody>\n' + row + '\n');
fs.writeFileSync(page, html);
console.log('stamped ' + ver + ' ' + sum[1]);
