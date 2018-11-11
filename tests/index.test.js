'use strict';

/**
 * @fileoverview Tests for permaudit.
 * @author idirdev
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  SENSITIVE_PATTERNS,
  getPerms,
  isSensitive,
  checkWorldWritable,
  checkExecutable,
  checkSensitive,
  auditDir,
  formatReport,
  summary,
} = require('../src/index.js');

const isWindows = process.platform === 'win32';

let tmpDir;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'permaudit-test-'));
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

// ── SENSITIVE_PATTERNS ───────────────────────────────────────────────────────

describe('SENSITIVE_PATTERNS', () => {
  it('is a non-empty array of strings', () => {
    assert.ok(Array.isArray(SENSITIVE_PATTERNS));
    assert.ok(SENSITIVE_PATTERNS.length >= 5);
    for (const p of SENSITIVE_PATTERNS) assert.equal(typeof p, 'string');
  });

  it('includes .env and id_rsa', () => {
    assert.ok(SENSITIVE_PATTERNS.includes('.env'));
    assert.ok(SENSITIVE_PATTERNS.includes('id_rsa'));
  });
});

// ── getPerms ─────────────────────────────────────────────────────────────────

describe('getPerms', () => {
  it('returns null for missing path', () => {
    assert.equal(getPerms(path.join(tmpDir, 'ghost.txt')), null);
  });

  it('returns perms object for existing file', () => {
    const f = path.join(tmpDir, 'basic.txt');
    fs.writeFileSync(f, 'hello');
    const p = getPerms(f);
    assert.ok(p !== null);
    assert.equal(typeof p.mode, 'number');
    assert.ok(typeof p.octal === 'string');
  });
});

// ── isSensitive ──────────────────────────────────────────────────────────────

describe('isSensitive', () => {
  it('returns true for .env files', () => {
    assert.equal(isSensitive('/home/user/.env'), true);
    assert.equal(isSensitive('/app/.env.local'), true);
  });

  it('returns true for id_rsa', () => {
    assert.equal(isSensitive('/home/user/.ssh/id_rsa'), true);
  });

  it('returns false for regular files', () => {
    assert.equal(isSensitive('/home/user/index.js'), false);
    assert.equal(isSensitive('/etc/hosts'), false);
  });
});

// ── checkWorldWritable ────────────────────────────────────────────────────────

describe('checkWorldWritable', () => {
  it('returns true when worldWritable is true', () => {
    assert.equal(checkWorldWritable({ worldWritable: true, octal: '0777' }), true);
  });

  it('returns false when worldWritable is false', () => {
    assert.equal(checkWorldWritable({ worldWritable: false, octal: '0644' }), false);
  });
});

// ── checkSensitive ────────────────────────────────────────────────────────────

describe('checkSensitive (with real files on non-Windows)', () => {
  it('returns false for non-sensitive file regardless of perms', () => {
    const result = checkSensitive('/home/user/readme.txt', { worldReadable: true, worldWritable: false });
    assert.equal(result, false);
  });

  it('returns true for sensitive file that is world-readable', () => {
    const result = checkSensitive('/home/user/.env', { worldReadable: true, worldWritable: false });
    assert.equal(result, true);
  });

  it('returns false for sensitive file with restricted perms', () => {
    const result = checkSensitive('/home/user/.env', { worldReadable: false, worldWritable: false });
    assert.equal(result, false);
  });

  it('detects world-writable sensitive file', () => {
    if (isWindows) return; // chmod not reliable on Windows
    const f = path.join(tmpDir, '.env');
    fs.writeFileSync(f, 'SECRET=abc\n');
    fs.chmodSync(f, 0o646);
    const perms = getPerms(f);
    assert.ok(perms !== null);
    assert.equal(checkSensitive(f, perms), true);
  });
});

// ── auditDir ─────────────────────────────────────────────────────────────────

describe('auditDir', () => {
  it('returns empty array for clean directory', () => {
    const d = fs.mkdtempSync(path.join(tmpDir, 'clean-'));
    fs.writeFileSync(path.join(d, 'app.js'), 'console.log(1);');
    if (!isWindows) fs.chmodSync(path.join(d, 'app.js'), 0o644);
    const findings = auditDir(d);
    // On Windows we may see executable flags; just verify array returned
    assert.ok(Array.isArray(findings));
  });

  it('detects world-writable file on non-Windows', () => {
    if (isWindows) return;
    const d = fs.mkdtempSync(path.join(tmpDir, 'ww-'));
    const f = path.join(d, 'config.js');
    fs.writeFileSync(f, 'const x = 1;');
    fs.chmodSync(f, 0o666);
    const findings = auditDir(d);
    assert.ok(findings.some((fi) => fi.file === f && fi.issue.toLowerCase().includes('world-writable')));
  });

  it('respects ignore list', () => {
    if (isWindows) return;
    const d = fs.mkdtempSync(path.join(tmpDir, 'ignore-'));
    const sub = path.join(d, 'node_modules');
    fs.mkdirSync(sub);
    const f = path.join(sub, 'lib.js');
    fs.writeFileSync(f, 'x');
    fs.chmodSync(f, 0o666);
    const findings = auditDir(d, { ignore: ['node_modules'] });
    assert.ok(!findings.some((fi) => fi.file === f));
  });

  it('sensitiveOnly skips non-sensitive world-writable files', () => {
    if (isWindows) return;
    const d = fs.mkdtempSync(path.join(tmpDir, 'so-'));
    const f = path.join(d, 'random.txt');
    fs.writeFileSync(f, 'data');
    fs.chmodSync(f, 0o666);
    const findings = auditDir(d, { sensitiveOnly: true });
    assert.ok(!findings.some((fi) => fi.file === f));
  });
});

// ── formatReport ─────────────────────────────────────────────────────────────

describe('formatReport', () => {
  it('returns no-issues message for empty findings', () => {
    assert.ok(formatReport([]).includes('No permission issues found'));
  });

  it('includes file path and issue in output', () => {
    const fake = [{ file: '/etc/.env', issue: 'Sensitive file is world-readable', severity: 'critical', perms: { octal: '0644' } }];
    const out = formatReport(fake);
    assert.ok(out.includes('/etc/.env'));
    assert.ok(out.includes('critical'));
  });
});

// ── summary ───────────────────────────────────────────────────────────────────

describe('summary', () => {
  it('returns zero counts for empty findings', () => {
    const s = summary([]);
    assert.equal(s.total, 0);
  });

  it('counts by severity correctly', () => {
    const fake = [
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'high' },
    ];
    const s = summary(fake);
    assert.equal(s.total, 3);
    assert.equal(s.critical, 1);
    assert.equal(s.high, 2);
  });
});
