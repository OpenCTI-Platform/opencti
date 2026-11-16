import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { compareFindings } from '../compare.mjs';
import { normalizeEslint, normalizeOxlint, oxlintConfigRules } from '../normalize.mjs';

const baseDir = path.resolve('/lint-parity-base');
const f = (file, line, ruleId, severity = 'error') => ({ file, line, ruleId, severity });
const compare = (input) => compareFindings({ eslint: [], oxlint: [], oxlintRules: new Set(), eslintOnly: [], allowlist: [], ...input });

test('identical findings give no differences', () => {
  const result = compare({ eslint: [f('a.ts', 1, 'no-debugger')], oxlint: [f('a.ts', 1, 'no-debugger')], oxlintRules: new Set(['no-debugger']) });
  assert.deepEqual(result.onlyEslint, []);
  assert.deepEqual(result.onlyOxlint, []);
  assert.deepEqual(result.severityMismatch, []);
  assert.deepEqual(result.staleAllowlist, []);
});

test('counts duplicates: two eslint vs one oxlint on same key gives one onlyEslint', () => {
  const result = compare({
    eslint: [f('a.ts', 1, 'no-debugger'), f('a.ts', 1, 'no-debugger')],
    oxlint: [f('a.ts', 1, 'no-debugger')],
    oxlintRules: new Set(['no-debugger']),
  });
  assert.equal(result.onlyEslint.length, 1);
  assert.deepEqual(result.onlyOxlint, []);
});

test('reports onlyOxlint for oxlint-only finding', () => {
  const result = compare({ oxlint: [f('a.ts', 3, 'eqeqeq')], oxlintRules: new Set(['eqeqeq']) });
  assert.deepEqual(result.onlyOxlint, [f('a.ts', 3, 'eqeqeq')]);
  assert.deepEqual(result.onlyEslint, []);
});

test('severity mismatch is reported once, not as two differences', () => {
  const result = compare({
    eslint: [f('a.ts', 1, 'no-debugger', 'error')],
    oxlint: [f('a.ts', 1, 'no-debugger', 'warning')],
    oxlintRules: new Set(['no-debugger']),
  });
  assert.deepEqual(result.severityMismatch, [{ eslint: f('a.ts', 1, 'no-debugger', 'error'), oxlint: f('a.ts', 1, 'no-debugger', 'warning') }]);
  assert.deepEqual(result.onlyEslint, []);
  assert.deepEqual(result.onlyOxlint, []);
});

test('skips eslint findings for rules missing from oxlintRules and counts them', () => {
  const result = compare({ eslint: [f('a.ts', 1, '@stylistic/semi'), f('b.ts', 2, '@stylistic/semi')], oxlintRules: new Set(['no-debugger']) });
  assert.equal(result.eslintOnlySkipped['@stylistic/semi'], 2);
  assert.deepEqual(result.onlyEslint, []);
});

test('skips eslint findings for rules on eslintOnly list', () => {
  const result = compare({
    eslint: [f('a.ts', 1, 'no-debugger')],
    oxlintRules: new Set(['no-debugger']),
    eslintOnly: [{ rule: 'no-debugger', reason: 'x' }],
  });
  assert.equal(result.eslintOnlySkipped['no-debugger'], 1);
  assert.deepEqual(result.onlyEslint, []);
});

test('matches an ESLint @typescript-eslint finding with the oxlint eslint() finding of the folded rule', () => {
  const eslintResults = [{ filePath: path.join(baseDir, 'a.ts'), messages: [{ ruleId: '@typescript-eslint/no-unused-vars', line: 7, severity: 2 }] }];
  const oxlintReport = { diagnostics: [{ code: 'eslint(no-unused-vars)', severity: 'error', filename: 'a.ts', labels: [{ span: { line: 7 } }] }] };
  const result = compare({
    eslint: normalizeEslint(eslintResults, baseDir),
    oxlint: normalizeOxlint(oxlintReport, baseDir),
    // What @oxlint/migrate writes for ESLint's @typescript-eslint/no-unused-vars: the core id.
    oxlintRules: oxlintConfigRules({ rules: { 'no-unused-vars': 'error' } }),
  });
  assert.deepEqual(result.onlyEslint, []);
  assert.deepEqual(result.onlyOxlint, []);
  assert.deepEqual(result.severityMismatch, []);
  assert.deepEqual(result.eslintOnlySkipped, {});
});

test('a folded rule that only ESLint reports stays an ESLint-only difference', () => {
  const eslintResults = [{ filePath: path.join(baseDir, 'a.ts'), messages: [{ ruleId: '@typescript-eslint/no-unused-vars', line: 7, severity: 2 }] }];
  const result = compare({
    eslint: normalizeEslint(eslintResults, baseDir),
    oxlintRules: oxlintConfigRules({ rules: { 'no-unused-vars': 'error' } }),
  });
  assert.deepEqual(result.onlyEslint, [f('a.ts', 7, 'no-unused-vars')]);
});

test('an unfolded typescript rule keeps its @typescript-eslint id on both sides', () => {
  const eslintResults = [{ filePath: path.join(baseDir, 'a.ts'), messages: [{ ruleId: '@typescript-eslint/no-explicit-any', line: 2, severity: 2 }] }];
  const oxlintReport = { diagnostics: [{ code: 'typescript-eslint(no-explicit-any)', severity: 'error', filename: 'a.ts', labels: [{ span: { line: 2 } }] }] };
  const result = compare({
    eslint: normalizeEslint(eslintResults, baseDir),
    oxlint: normalizeOxlint(oxlintReport, baseDir),
    oxlintRules: oxlintConfigRules({ rules: { 'typescript/no-explicit-any': 'error' } }),
  });
  assert.deepEqual(result.onlyEslint, []);
  assert.deepEqual(result.onlyOxlint, []);
});

test('allowlist with glob removes only matching files', () => {
  const result = compare({
    oxlint: [f('src/legacy/a.ts', 1, 'eqeqeq'), f('src/b.ts', 1, 'eqeqeq')],
    oxlintRules: new Set(['eqeqeq']),
    allowlist: [{ rule: 'eqeqeq', files: 'src/legacy/**', reason: 'x' }],
  });
  assert.deepEqual(result.onlyOxlint, [f('src/b.ts', 1, 'eqeqeq')]);
  assert.deepEqual(result.staleAllowlist, []);
});

test('allowlist without files matches the rule everywhere and also clears onlyEslint and severityMismatch', () => {
  const result = compare({
    eslint: [f('a.ts', 1, 'eqeqeq'), f('a.ts', 2, 'eqeqeq', 'error')],
    oxlint: [f('a.ts', 2, 'eqeqeq', 'warning')],
    oxlintRules: new Set(['eqeqeq']),
    allowlist: [{ rule: 'eqeqeq', reason: 'x' }],
  });
  assert.deepEqual(result.onlyEslint, []);
  assert.deepEqual(result.severityMismatch, []);
  assert.deepEqual(result.staleAllowlist, []);
});

test('reports stale allowlist entries', () => {
  const entry = { rule: 'no-console', reason: 'x' };
  const result = compare({ allowlist: [entry] });
  assert.deepEqual(result.staleAllowlist, [entry]);
});
