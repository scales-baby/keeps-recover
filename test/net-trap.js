// No-network runtime proof. Loads keeps-recover as the main module after replacing every
// Node network entry point with a trap that records the call and throws. At exit it
// writes a JSON report to the path in argv[2]. Usage:
//   node test/net-trap.js <report.json> keeps-recover.js [tool args...]
'use strict';
const fs = require('fs');
const path = require('path');
const Module = require('module');

const report = process.argv[2];
const hits = [];
function trap(obj, name, label) {
  if (!obj || typeof obj[name] !== 'function') return;
  obj[name] = function trapped() { hits.push(label); throw new Error('network blocked by test: ' + label); };
}
const net = require('net');
trap(net, 'connect', 'net.connect'); trap(net, 'createConnection', 'net.createConnection');
trap(net, 'createServer', 'net.createServer');
trap(net.Socket.prototype, 'connect', 'net.Socket.connect');
trap(net.Server.prototype, 'listen', 'net.Server.listen');
const dns = require('dns');
for (const k of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'reverse', 'lookupService']) trap(dns, k, 'dns.' + k);
for (const k of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'reverse']) trap(dns.promises, k, 'dns.promises.' + k);
for (const mod of ['http', 'https']) { const m = require(mod); trap(m, 'request', mod + '.request'); trap(m, 'get', mod + '.get'); trap(m, 'createServer', mod + '.createServer'); }
trap(require('http2'), 'connect', 'http2.connect');
trap(require('tls'), 'connect', 'tls.connect');
trap(require('dgram'), 'createSocket', 'dgram.createSocket');
trap(globalThis, 'fetch', 'fetch');
if (globalThis.WebSocket) globalThis.WebSocket = function () { hits.push('WebSocket'); throw new Error('blocked'); };

process.on('exit', (code) => {
  fs.writeFileSync(report, JSON.stringify({ code, hits }));
});

process.argv = [process.argv[0], path.resolve(process.argv[3]), ...process.argv.slice(4)];
Module.runMain();
