#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { inspectFile } from '../src/index.js';

function usage() {
  return 'Usage: credential-lens inspect --file <path> [--format json|text] [--unlock]';
}

const args = process.argv.slice(2);
if (args[0] !== 'inspect') {
  process.stderr.write(`${usage()}\n`);
  process.exitCode = 2;
} else {
  const fileIndex = args.indexOf('--file');
  const formatIndex = args.indexOf('--format');
  const path = fileIndex >= 0 ? args[fileIndex + 1] : null;
  const format = formatIndex >= 0 ? args[formatIndex + 1] : 'json';
  if (!path || !['json', 'text'].includes(format)) {
    process.stderr.write(`${usage()}\n`);
    process.exitCode = 2;
  } else {
    try {
      const report = await inspectFile(path);
      if (args.includes('--unlock')) {
        if (!process.stdin.isTTY) throw new Error('--unlock requires an interactive terminal');
        const unlock = spawnSync('ssh-keygen', ['-y', '-f', path], { encoding: 'utf8', stdio: ['inherit', 'pipe', 'inherit'] });
        report.unlock = { attempted: true, succeeded: unlock.status === 0 };
        if (!report.unlock.succeeded) report.unlock.error = 'OpenSSH could not unlock the private key.';
      }
      if (format === 'json') process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      else {
        const facts = report.facts;
        if (facts.kind === 'jwt') {
          const newline = String.fromCharCode(10);
          process.stdout.write('JWT header: ' + JSON.stringify(facts.header) + newline);
          process.stdout.write('JWT payload: ' + JSON.stringify(facts.payload) + newline);
          if (Object.keys(facts.timestamps).length) process.stdout.write('JWT timestamps: ' + JSON.stringify(facts.timestamps) + newline);
        }
        process.stdout.write(`Status: ${report.status}\nKind: ${facts.kind || 'unknown'}\nContainer: ${facts.container || 'unknown'}\n`);
        for (const key of facts.publicKeys || []) process.stdout.write(`Key: ${key.algorithm}${key.bits ? ` (${key.bits} bits)` : ''}\n`);
        if (facts.encryption) process.stdout.write(`Encrypted: ${facts.encryption.encrypted ? 'yes' : 'no'}\n`);
        for (const caveat of report.caveats) process.stdout.write(`Caveat: ${caveat}\n`);
      }
      if (report.status !== 'ok') process.exitCode = 1;
    } catch (error) {
      process.stderr.write(`credential-lens: ${error.message}\n`);
      process.exitCode = 1;
    }
  }
}
