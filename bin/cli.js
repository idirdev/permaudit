#!/usr/bin/env node
'use strict';

/**
 * @fileoverview CLI for permaudit — audit file permissions for security issues.
 * @author idirdev
 */

const path = require('path');
const fs = require('fs');
const { auditDir, formatReport, summary, getPerms } = require('../src/index.js');

const args = process.argv.slice(2);

function printHelp() {
  console.log(`
Usage: permaudit [dir] [options]

Options:
  --recursive        Recurse into subdirectories (default: true)
  --sensitive-only   Only report issues with sensitive files
  --json             Output findings as JSON
  --fix              Attempt to fix world-writable bits (chmod o-w)
  -h, --help         Show this help message
`.trim());
}

if (args.includes('-h') || args.includes('--help')) {
  printHelp();
  process.exit(0);
}

const dir = (!args[0] || args[0].startsWith('--')) ? process.cwd() : path.resolve(args[0]);
const recursive    = !args.includes('--no-recursive');
const sensitiveOnly = args.includes('--sensitive-only');
const useJson      = args.includes('--json');
const fix          = args.includes('--fix');

const findings = auditDir(dir, { recursive, sensitiveOnly });

if (fix) {
  let fixed = 0;
  for (const f of findings) {
    if (f.issue.toLowerCase().includes('world-writable')) {
      try {
        const stat = fs.statSync(f.file);
        fs.chmodSync(f.file, stat.mode & ~0o002);
        fixed++;
      } catch (e) {
        console.error(`Could not fix ${f.file}: ${e.message}`);
      }
    }
  }
  console.log(`Fixed ${fixed} world-writable item(s).`);
}

if (useJson) {
  console.log(JSON.stringify(findings, null, 2));
} else {
  process.stdout.write(formatReport(findings));
  const s = summary(findings);
  console.log(`\nSummary: ${s.total} issue(s) | critical: ${s.critical} | high: ${s.high} | medium: ${s.medium} | low: ${s.low}`);
}

process.exit(findings.length > 0 ? 1 : 0);
