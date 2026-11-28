import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(here, '..', 'cli.mjs');
const fixture = path.join(here, 'fixtures', 'pkg');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lint-parity-test-'));
test.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

const readFixture = (name) => JSON.parse(fs.readFileSync(path.join(fixture, name), 'utf8'));
const writeTmp = (name, content) => {
  const file = path.join(tmpDir, name);
  fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
  return file;
};

const runCli = ({ packageDir = fixture, eslint = path.join(fixture, 'eslint.json'), oxlint = path.join(fixture, 'oxlint.json') } = {}) => spawnSync(
  process.execPath,
  [cli, '--package-dir', packageDir, '--eslint-output', eslint, '--oxlint-output', oxlint],
  { encoding: 'utf8' },
);

test('exits 0 and prints "parity: OK" when outputs match', () => {
  const run = runCli();
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.ok(run.stdout.includes('parity: OK'));
  assert.ok(run.stdout.includes('@stylistic/semi: 1'), 'skipped ESLint-only findings are reported');
});

test('exits 1 and lists the rule in the summary when outputs differ', () => {
  const oxlint = readFixture('oxlint.json');
  oxlint.diagnostics.push({
    code: 'eslint(eqeqeq)', severity: 'error', filename: 'src/c.ts', labels: [{ span: { line: 7, column: 1 } }],
  });
  const run = runCli({ oxlint: writeTmp('oxlint-extra.json', oxlint) });
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.ok(run.stdout.includes('eqeqeq'));
  assert.ok(run.stdout.includes('only oxlint'));
  assert.ok(run.stdout.includes('src/c.ts:7 eqeqeq'));
});

test('exits 1 when file counts differ', () => {
  const eslint = readFixture('eslint.json');
  const oxlint = { ...readFixture('oxlint.json'), number_of_files: 4 };
  const run = runCli({ eslint: writeTmp('eslint-3.json', eslint), oxlint: writeTmp('oxlint-4.json', oxlint) });
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.ok(run.stdout.includes('files: eslint 3, oxlint 4'));
  assert.ok(!run.stdout.includes('parity: OK'));
});

test('exits 1 and says to remove a stale allowlist entry', () => {
  const eslint = readFixture('eslint.json');
  eslint[1].messages = [];
  const run = runCli({ eslint: writeTmp('eslint-no-b.json', eslint) });
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.ok(run.stdout.includes('matches no remaining difference — remove it'));
});

test('exits 2 when a tool output is not valid JSON', () => {
  const run = runCli({ eslint: writeTmp('eslint-broken.json', '{ not json') });
  assert.equal(run.status, 2);
  assert.ok(run.stderr.includes('not valid JSON'));
});

test('exits 2 when oxlint checked no files', () => {
  const oxlint = { ...readFixture('oxlint.json'), number_of_files: 0 };
  const run = runCli({ oxlint: writeTmp('oxlint-0.json', oxlint) });
  assert.equal(run.status, 2);
});

test('exits 2 when a binary is missing and no output file is given', () => {
  const run = spawnSync(process.execPath, [cli, '--package-dir', fixture], { encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.ok(run.stderr.includes('eslint binary not found'));
});

for (const list of ['allowlist', 'eslintOnly']) {
  test(`exits 2 when an ${list} entry has no reason`, () => {
    const packageDir = fs.mkdtempSync(path.join(tmpDir, 'pkg-'));
    fs.copyFileSync(path.join(fixture, '.oxlintrc.json'), path.join(packageDir, '.oxlintrc.json'));
    fs.writeFileSync(path.join(packageDir, 'lint-parity.json'), JSON.stringify({ [list]: [{ rule: 'no-reasonless-rule' }] }));
    const run = runCli({ packageDir });
    assert.equal(run.status, 2);
    assert.ok(run.stderr.includes('no-reasonless-rule'));
  });
}
