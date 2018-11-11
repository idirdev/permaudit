'use strict';

/**
 * @fileoverview Audit file and directory permissions for security issues.
 * @module permaudit
 * @author idirdev
 */

const fs = require('fs');
const path = require('path');

/**
 * Sensitive file name patterns that require restricted permissions.
 * @type {string[]}
 */
const SENSITIVE_PATTERNS = ['.env', '.pem', 'id_rsa', '.key', 'credentials', '.secret'];

/**
 * Get permission information for a file or directory.
 * @param {string} filePath - Path to the file or directory.
 * @returns {{mode: number, octal: string, readable: boolean, writable: boolean, executable: boolean, worldReadable: boolean, worldWritable: boolean, worldExecutable: boolean} | null}
 */
function getPerms(filePath) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch {
    return null;
  }

  const mode = stat.mode;
  const octal = (mode & 0o7777).toString(8).padStart(4, '0');

  return {
    mode,
    octal,
    readable:        Boolean(mode & 0o400),
    writable:        Boolean(mode & 0o200),
    executable:      Boolean(mode & 0o100),
    worldReadable:   Boolean(mode & 0o004),
    worldWritable:   Boolean(mode & 0o002),
    worldExecutable: Boolean(mode & 0o001),
  };
}

/**
 * Check whether a path is a sensitive file based on name patterns.
 * @param {string} filePath
 * @returns {boolean}
 */
function isSensitive(filePath) {
  const name = path.basename(filePath).toLowerCase();
  return SENSITIVE_PATTERNS.some((p) => name.includes(p));
}

/**
 * Check if permissions on a world-writable path are problematic.
 * @param {{octal: string, worldWritable: boolean}} perms
 * @returns {boolean}
 */
function checkWorldWritable(perms) {
  return perms.worldWritable === true;
}

/**
 * Check if an executable file is unexpected (not in a bin/ directory).
 * @param {string} filePath
 * @param {{executable: boolean}} perms
 * @returns {boolean}
 */
function checkExecutable(filePath, perms) {
  if (!perms.executable) return false;
  const normalized = filePath.replace(/\\/g, '/');
  const inBin = /\/bin\/|node_modules\/.bin\//.test(normalized);
  const ext = path.extname(filePath).toLowerCase();
  const scriptExt = ['.js', '.ts', '.sh', '.py', '.rb', '.pl', '.bash'];
  if (inBin) return false;
  if (scriptExt.includes(ext)) return false;
  return true;
}

/**
 * Check if a sensitive file has overly permissive permissions.
 * @param {string} filePath
 * @param {{worldReadable: boolean, worldWritable: boolean}} perms
 * @returns {boolean}
 */
function checkSensitive(filePath, perms) {
  if (!isSensitive(filePath)) return false;
  return perms.worldReadable || perms.worldWritable;
}

/**
 * Audit a directory recursively for permission issues.
 * @param {string} dir - Directory to audit.
 * @param {object} [opts={}] - Options.
 * @param {boolean} [opts.recursive=true] - Recurse into subdirectories.
 * @param {boolean} [opts.sensitiveOnly=false] - Only report sensitive file issues.
 * @param {string[]} [opts.ignore=['.git','node_modules']] - Path segments to skip.
 * @returns {Array<{file: string, issue: string, severity: string, perms: object}>}
 */
function auditDir(dir, opts = {}) {
  const recursive = opts.recursive !== false;
  const sensitiveOnly = opts.sensitiveOnly || false;
  const ignore = opts.ignore || ['.git', 'node_modules'];
  const findings = [];

  function walk(current) {
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const skip = ignore.some((ig) => fullPath.includes(ig));
      if (skip) continue;

      const perms = getPerms(fullPath);
      if (!perms) continue;

      if (entry.isDirectory()) {
        if (checkWorldWritable(perms)) {
          findings.push({
            file: fullPath,
            issue: 'World-writable directory',
            severity: 'high',
            perms,
          });
        }
        if (recursive) walk(fullPath);
      } else if (entry.isFile()) {
        if (checkSensitive(fullPath, perms)) {
          findings.push({
            file: fullPath,
            issue: 'Sensitive file is world-readable or world-writable',
            severity: 'critical',
            perms,
          });
        } else if (!sensitiveOnly && checkWorldWritable(perms)) {
          findings.push({
            file: fullPath,
            issue: 'World-writable file',
            severity: 'high',
            perms,
          });
        } else if (!sensitiveOnly && checkExecutable(fullPath, perms)) {
          findings.push({
            file: fullPath,
            issue: 'Unexpected executable bit set',
            severity: 'medium',
            perms,
          });
        }
      }
    }
  }

  walk(dir);
  return findings;
}

/**
 * Format audit findings as a human-readable report string.
 * @param {Array<{file: string, issue: string, severity: string, perms: object}>} findings
 * @returns {string}
 */
function formatReport(findings) {
  if (findings.length === 0) return 'No permission issues found.\n';

  const lines = ['Permission Audit Report', '='.repeat(50)];
  for (const f of findings) {
    lines.push(`\nFile    : ${f.file}`);
    lines.push(`Issue   : ${f.issue}`);
    lines.push(`Severity: ${f.severity}`);
    lines.push(`Mode    : ${f.perms.octal}`);
  }
  return lines.join('\n') + '\n';
}

/**
 * Summarize findings by severity.
 * @param {Array<{severity: string}>} findings
 * @returns {{total: number, critical: number, high: number, medium: number, low: number}}
 */
function summary(findings) {
  const counts = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  return counts;
}

module.exports = {
  SENSITIVE_PATTERNS,
  getPerms,
  isSensitive,
  checkWorldWritable,
  checkExecutable,
  checkSensitive,
  auditDir,
  formatReport,
  summary,
};
