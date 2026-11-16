import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { normalizeEslint, normalizeOxlint, oxlintConfigRules, toComparableRuleId, toEslintRuleId } from '../normalize.mjs';

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const readFixture = (name) => fs.readFileSync(path.join(fixtureDir, name), 'utf8');

// Real oxlint 1.93.0 `--format json` shape (captured, run from the fixtures dir):
//   { diagnostics: [{ code: 'eslint(no-debugger)', severity: 'error'|'warning', filename: 'sample-src/a.ts',
//                     labels: [{ span: { line, column, offset, length } }] }], number_of_files, number_of_rules, threads_count, start_time }
//   - file: `filename`, relative to the directory oxlint ran in
//   - line: `labels[0].span.line`
//   - rule: `code`, formatted `plugin(rule)`
//   - severity: `severity`
//   - files checked: `number_of_files`
const oxlintSample = JSON.parse(readFixture('oxlint-sample.json'));
// ESLint filePath is absolute; the fixture holds a placeholder so it works on any machine.
const eslintSample = JSON.parse(readFixture('eslint-sample.json').replaceAll('__BASE_DIR__', fixtureDir.split(path.sep).join('/')));

test('maps oxlint config keys and diagnostic codes to ESLint ids', () => {
  assert.equal(toEslintRuleId('eslint(no-debugger)'), 'no-debugger');
  assert.equal(toEslintRuleId('no-debugger'), 'no-debugger');
  assert.equal(toEslintRuleId('typescript-eslint(no-unused-vars)'), '@typescript-eslint/no-unused-vars');
  assert.equal(toEslintRuleId('typescript(no-explicit-any)'), '@typescript-eslint/no-explicit-any');
  assert.equal(toEslintRuleId('typescript/no-unused-vars'), '@typescript-eslint/no-unused-vars');
  assert.equal(toEslintRuleId('@typescript-eslint/no-unused-vars'), '@typescript-eslint/no-unused-vars');
  assert.equal(toEslintRuleId('eslint-plugin-react(jsx-key)'), 'react/jsx-key');
  assert.equal(toEslintRuleId('react(jsx-key)'), 'react/jsx-key');
  assert.equal(toEslintRuleId('react/jsx-key'), 'react/jsx-key');
  assert.equal(toEslintRuleId('react_hooks/rules-of-hooks'), 'react-hooks/rules-of-hooks');
  assert.equal(toEslintRuleId('eslint-plugin-import(no-cycle)'), 'import/no-cycle');
  assert.equal(toEslintRuleId('eslint-plugin-jsx-a11y(alt-text)'), 'jsx-a11y/alt-text');
  assert.equal(toEslintRuleId('jsx-a11y(alt-text)'), 'jsx-a11y/alt-text');
  assert.equal(toEslintRuleId('jsx_a11y/alt-text'), 'jsx-a11y/alt-text');
  assert.equal(toEslintRuleId('unicorn(no-null)'), 'unicorn/no-null');
  assert.equal(toEslintRuleId('promise(param-names)'), 'promise/param-names');
  assert.equal(toEslintRuleId('node(no-exports-assign)'), 'n/no-exports-assign');
});

test('keeps an unknown plugin prefix as-is', () => {
  assert.equal(toEslintRuleId('mystery(some-rule)'), 'mystery/some-rule');
  assert.equal(toEslintRuleId('mystery/some-rule'), 'mystery/some-rule');
});

test('normalizes absolute and relative paths to the same key', () => {
  const eslintFiles = normalizeEslint(eslintSample, fixtureDir).map((f) => f.file).sort();
  const oxlintFiles = normalizeOxlint(oxlintSample, fixtureDir).map((f) => f.file).sort();
  assert.deepEqual(eslintFiles, oxlintFiles);
  assert.deepEqual([...new Set(eslintFiles)], ['sample-src/a.ts']);
  for (const file of [...eslintFiles, ...oxlintFiles]) {
    assert.ok(!file.startsWith('./') && !file.includes('\\'));
  }
});

test('normalizes ESLint and oxlint to the same lines', () => {
  const key = (f) => `${f.file}:${f.line}`;
  assert.deepEqual(normalizeEslint(eslintSample, fixtureDir).map(key).sort(), normalizeOxlint(oxlintSample, fixtureDir).map(key).sort());
});

test('drops diagnostics without a rule id', () => {
  assert.equal(eslintSample[0].messages.length, 4);
  assert.equal(normalizeEslint(eslintSample, fixtureDir).length, 3);
  const withoutCode = { diagnostics: [...oxlintSample.diagnostics, { severity: 'error', message: 'parse error', filename: 'sample-src/a.ts', labels: [] }] };
  assert.equal(normalizeOxlint(withoutCode, fixtureDir).length, 3);
});

test('maps severities to error|warning', () => {
  const eslint = normalizeEslint(eslintSample, fixtureDir);
  assert.equal(eslint.find((f) => f.ruleId === 'no-debugger').severity, 'error');
  assert.equal(eslint.find((f) => f.ruleId === 'no-unused-vars').severity, 'warning');
  const oxlint = normalizeOxlint(oxlintSample, fixtureDir);
  assert.equal(oxlint.find((f) => f.ruleId === 'no-debugger').severity, 'error');
  // oxlint reports the rule migrate folds into the core id with an eslint(...) code; ESLint's @typescript-eslint form folds to the same id.
  assert.equal(oxlint.find((f) => f.ruleId === 'no-unused-vars').severity, 'warning');
});

test('produces the Finding shape', () => {
  assert.deepEqual(normalizeEslint(eslintSample, fixtureDir)[0], { file: 'sample-src/a.ts', line: 2, ruleId: 'no-debugger', severity: 'error' });
  assert.deepEqual(normalizeOxlint(oxlintSample, fixtureDir).find((f) => f.ruleId === 'eqeqeq'), { file: 'sample-src/a.ts', line: 4, ruleId: 'eqeqeq', severity: 'error' });
});

test('oxlintConfigRules collects top-level and override rules, skips off', () => {
  const rules = oxlintConfigRules({
    rules: { 'no-debugger': 'error', eqeqeq: 'off' },
    overrides: [{ files: ['*.ts'], rules: { 'typescript/no-unused-vars': ['warn', {}] } }],
  });
  assert.deepEqual([...rules].sort(), ['no-debugger', 'no-unused-vars']);
});

test('oxlintConfigRules handles numeric levels and missing sections', () => {
  assert.deepEqual([...oxlintConfigRules({})], []);
  assert.deepEqual([...oxlintConfigRules({ rules: { eqeqeq: 0, 'no-debugger': 1, 'react/jsx-key': ['off', {}] } })].sort(), ['no-debugger']);
});

test('oxlintConfigRules treats the allow alias as off', () => {
  assert.deepEqual([...oxlintConfigRules({ rules: { eqeqeq: 'allow', 'no-debugger': ['allow', {}], 'no-console': 'warn' } })], ['no-console']);
});

test('toComparableRuleId folds the @typescript-eslint rules oxlint enforces under the core id', () => {
  for (const core of ['no-unused-vars', 'no-array-constructor', 'no-unused-expressions', 'no-shadow', 'no-redeclare']) {
    assert.equal(toComparableRuleId(`@typescript-eslint/${core}`), core);
    assert.equal(toComparableRuleId(core), core);
  }
});

test('toComparableRuleId keeps every other id', () => {
  assert.equal(toComparableRuleId('@typescript-eslint/no-explicit-any'), '@typescript-eslint/no-explicit-any');
  assert.equal(toComparableRuleId('@typescript-eslint/naming-convention'), '@typescript-eslint/naming-convention');
  assert.equal(toComparableRuleId('react/jsx-key'), 'react/jsx-key');
  assert.equal(toComparableRuleId('eqeqeq'), 'eqeqeq');
});

test('toComparableRuleId is idempotent and composes with toEslintRuleId', () => {
  assert.equal(toComparableRuleId(toComparableRuleId('@typescript-eslint/no-unused-vars')), 'no-unused-vars');
  assert.equal(toComparableRuleId(toEslintRuleId('typescript/no-unused-vars')), 'no-unused-vars');
  assert.equal(toComparableRuleId(toEslintRuleId('typescript-eslint(no-unused-vars)')), 'no-unused-vars');
  assert.equal(toComparableRuleId(toEslintRuleId('eslint(no-unused-vars)')), 'no-unused-vars');
});
