import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// PowerShell 7.3+ reserves begin/process/end/clean/dynamicparam as the first word of a script block.
// Windows PowerShell 5.1 does not, so a helper named after one of them parses locally but fails on CI.
const reserved = ['begin', 'process', 'end', 'clean', 'dynamicparam'];
const files = [];
(function walk(dir) { for (const e of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, e.name); if (e.isDirectory()) walk(p); else if (p.endsWith('.ps1')) files.push(p); } })('scripts');

test('PowerShell scripts parse the same on Windows PowerShell 5.1 and PowerShell 7', () => {
  assert.ok(files.length >= 10);
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const word of reserved) {
      assert.doesNotMatch(text, new RegExp(`function\\s+${word}\\b`, 'i'), `${file} defines a function named ${word}`);
      assert.doesNotMatch(text, new RegExp(`\\{\\s*${word}\\s+[$('"\\w]`, 'i'), `${file} starts a script block with ${word}`);
    }
    assert.doesNotMatch(text, /[^\x00-\x7f]/, `${file} must stay ASCII so both PowerShell versions read it the same`);
    for (const call of text.match(/ConvertTo-Json[^)\r\n]*/g) || []) assert.match(call, /-Compress/, `${file}: ${call} must use -Compress (indented JSON is about 5x larger; a real 807-rule firewall export exceeded the 2 MiB ingest limit)`);
  }
});
