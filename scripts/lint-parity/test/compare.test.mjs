import assert from 'node:assert/strict';
import test from 'node:test';
import { compareFindings } from '../compare.mjs';
import { oxlintConfigRules } from '../normalize.mjs';

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

test('treats aliased rule as covered', () => {
  const result = compare({
    eslint: [f('a.ts', 1, '@typescript-eslint/no-unused-vars')],
    oxlintRules: oxlintConfigRules({ rules: { 'typescript/no-unused-vars': 'error' } }),
  });
  assert.deepEqual(result.onlyEslint, [f('a.ts', 1, '@typescript-eslint/no-unused-vars')]);
  assert.deepEqual(result.eslintOnlySkipped, {});
});

test('re-keys oxlint eslint() code to its typescript config rule', () => {
  const result = compare({
    eslint: [f('a.ts', 1, '@typescript-eslint/no-unused-vars')],
    oxlint: [f('a.ts', 1, 'no-unused-vars')],
    oxlintRules: oxlintConfigRules({ rules: { 'typescript/no-unused-vars': 'error' } }),
  });
  assert.deepEqual(result.onlyEslint, []);
  assert.deepEqual(result.onlyOxlint, []);
  assert.deepEqual(result.severityMismatch, []);
});

test('does not re-key an oxlint rule that is itself configured', () => {
  const result = compare({
    oxlint: [f('a.ts', 1, 'no-unused-vars')],
    oxlintRules: new Set(['no-unused-vars', '@typescript-eslint/no-unused-vars']),
  });
  assert.deepEqual(result.onlyOxlint, [f('a.ts', 1, 'no-unused-vars')]);
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
