#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { normalizeEslint, normalizeOxlint, oxlintConfigRules } from './normalize.mjs';
import { compareFindings } from './compare.mjs';
import { exitCode, formatReport } from './report.mjs';

const EXIT_TOOL_ERROR = 2;
const MAX_BUFFER = 512 * 1024 * 1024;

class ToolError extends Error {}

const readJson = (file, label) => {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (error) {
    throw new ToolError(`cannot read ${label} (${file}): ${error.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new ToolError(`${label} (${file}) is not valid JSON: ${error.message}`);
  }
};

const readParityConfig = (packageDir) => {
  const file = path.join(packageDir, 'lint-parity.json');
  const config = fs.existsSync(file) ? readJson(file, 'lint-parity.json') : {};
  const eslintOnly = config.eslintOnly ?? [];
  const allowlist = config.allowlist ?? [];
  if (!Array.isArray(eslintOnly) || !Array.isArray(allowlist)) {
    throw new ToolError('lint-parity.json: "eslintOnly" and "allowlist" must be arrays');
  }
  const check = (list, name) => list.forEach((entry) => {
    if (typeof entry?.rule !== 'string' || entry.rule === '') {
      throw new ToolError(`lint-parity.json: a ${name} entry has no rule`);
    }
    if (typeof entry.reason !== 'string' || entry.reason.trim() === '') {
      throw new ToolError(`lint-parity.json: ${name} entry "${entry.rule}" has no reason`);
    }
  });
  check(eslintOnly, 'eslintOnly');
  check(allowlist, 'allowlist');
  return { eslintOnly, allowlist };
};

const binaryPath = (packageDir, name) => {
  const binary = path.join(packageDir, 'node_modules', '.bin', name);
  if (!fs.existsSync(binary)) throw new ToolError(`${name} binary not found at ${binary}`);
  return binary;
};

const runTool = (name, binary, args, packageDir) => {
  const run = spawnSync(binary, args, { cwd: packageDir, encoding: 'utf8', maxBuffer: MAX_BUFFER });
  if (run.error) throw new ToolError(`${name} failed to run: ${run.error.message}`);
  // Both tools exit 1 when they find errors, which is not a crash.
  if (run.status !== 0 && run.status !== 1) {
    throw new ToolError(`${name} crashed (exit ${run.status ?? run.signal}): ${(run.stderr || run.stdout).trim().slice(0, 2000)}`);
  }
  return run;
};

const runEslint = (packageDir) => {
  const binary = binaryPath(packageDir, 'eslint');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-parity-'));
  const outputFile = path.join(tmpDir, 'eslint.json');
  try {
    runTool('eslint', binary, ['--config', 'eslint.config.ts', '--format', 'json', '--output-file', outputFile], packageDir);
    return readJson(outputFile, 'eslint output');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
};

const runOxlint = (packageDir) => {
  const binary = binaryPath(packageDir, 'oxlint');
  const run = runTool('oxlint', binary, ['-c', '.oxlintrc.json', '--format', 'json'], packageDir);
  try {
    return JSON.parse(run.stdout);
  } catch (error) {
    throw new ToolError(`oxlint output is not valid JSON: ${error.message}`);
  }
};

const main = () => {
  const { values } = parseArgs({
    options: {
      'package-dir': { type: 'string' },
      'eslint-output': { type: 'string' },
      'oxlint-output': { type: 'string' },
    },
  });
  const packageDir = path.resolve(values['package-dir'] ?? process.cwd());

  const { eslintOnly, allowlist } = readParityConfig(packageDir);
  const oxlintrc = readJson(path.join(packageDir, '.oxlintrc.json'), '.oxlintrc.json');
  const eslintResults = values['eslint-output'] === undefined
    ? runEslint(packageDir)
    : readJson(path.resolve(values['eslint-output']), 'eslint output');
  const oxlintReport = values['oxlint-output'] === undefined
    ? runOxlint(packageDir)
    : readJson(path.resolve(values['oxlint-output']), 'oxlint output');

  if (!Array.isArray(eslintResults)) throw new ToolError('eslint output is not a results array');
  if (!Array.isArray(oxlintReport?.diagnostics)) throw new ToolError('oxlint output has no diagnostics array');
  const eslintFiles = eslintResults.length;
  const oxlintFiles = oxlintReport.number_of_files;
  if (!Number.isInteger(oxlintFiles)) throw new ToolError('oxlint output has no number_of_files');
  if (eslintFiles === 0 || oxlintFiles === 0) {
    throw new ToolError(`a tool checked no files (files: eslint ${eslintFiles}, oxlint ${oxlintFiles})`);
  }

  const result = compareFindings({
    eslint: normalizeEslint(eslintResults, packageDir),
    oxlint: normalizeOxlint(oxlintReport, packageDir),
    oxlintRules: oxlintConfigRules(oxlintrc),
    eslintOnly,
    allowlist,
  });

  const countsDiffer = eslintFiles !== oxlintFiles;
  const report = formatReport(result);
  if (countsDiffer) {
    console.log('parity: DIFFERENCES');
    console.log(`files: eslint ${eslintFiles}, oxlint ${oxlintFiles}`);
    if (exitCode(result) !== 0) console.log(report.split('\n').slice(1).join('\n'));
    return 1;
  }
  console.log(report);
  return exitCode(result);
};

try {
  process.exitCode = main();
} catch (error) {
  // Anything that is not a difference is a tool or usage error, including a bad flag.
  console.error(`lint-parity: ${error instanceof ToolError ? error.message : error.stack}`);
  process.exitCode = EXIT_TOOL_ERROR;
}
