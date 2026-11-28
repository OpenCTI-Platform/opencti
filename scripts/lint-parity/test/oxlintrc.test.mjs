import test from 'node:test';
import assert from 'node:assert/strict';
import { anchorOverrideGlobs, compareConfigs, excludeBlockIgnores, rootAnchorGlob, serializeConfig } from '../oxlintrc.mjs';

test('anchors a slash-less pattern to the package root', () => {
  assert.equal(rootAnchorGlob('*.js'), './*.js');
  assert.equal(rootAnchorGlob('knip.ts'), './knip.ts');
  assert.equal(rootAnchorGlob('*.{js,ts}'), './*.{js,ts}');
});

test('leaves patterns with a slash, anchored or negated patterns alone', () => {
  for (const pattern of ['**/*.ts', 'src/*.js', './*.js', 'tests/**', '**/*.{js,cjs}', '!*.js']) {
    assert.equal(rootAnchorGlob(pattern), pattern);
  }
});

test('rewrites the slash-less patterns of every override and reports them with the override index', () => {
  const config = {
    rules: { eqeqeq: 'error' },
    overrides: [
      { files: ['**/*.ts'], rules: { a: 'off' } },
      { files: ['*.js'], rules: { b: 'off' } },
      { files: ['builder/**/*.{ts,cts}', 'knip.ts'], rules: { c: 'off' } },
    ],
  };
  const { config: result, rewritten } = anchorOverrideGlobs(config);
  assert.deepEqual(result.overrides.map((override) => override.files), [
    ['**/*.ts'],
    ['./*.js'],
    ['builder/**/*.{ts,cts}', './knip.ts'],
  ]);
  assert.deepEqual(rewritten, [
    { override: 1, before: '*.js', after: './*.js' },
    { override: 2, before: 'knip.ts', after: './knip.ts' },
  ]);
  // The rules and the rest of each override are untouched, and the input is not mutated.
  assert.deepEqual(result.overrides[1].rules, { b: 'off' });
  assert.equal(config.overrides[1].files[0], '*.js');
});

test('handles a config without overrides', () => {
  const config = { rules: {} };
  assert.deepEqual(anchorOverrideGlobs(config), { config, rewritten: [] });
});

test('is idempotent', () => {
  const once = anchorOverrideGlobs({ overrides: [{ files: ['*.js'] }] }).config;
  const twice = anchorOverrideGlobs(once);
  assert.deepEqual(twice.config, once);
  assert.deepEqual(twice.rewritten, []);
});

test('serializes with two-space indentation and a trailing newline', () => {
  assert.equal(serializeConfig({ a: [1] }), '{\n  "a": [\n    1\n  ]\n}\n');
});

test('compareConfigs: identical text matches', () => {
  assert.deepEqual(compareConfigs('{\n}\n', '{\n}\n'), { match: true, reason: '' });
});

test('compareConfigs: reports the first differing line', () => {
  const result = compareConfigs('a\nb\nc\n', 'a\nX\nc\n');
  assert.equal(result.match, false);
  assert.match(result.reason, /first difference at line 2/);
});

test('compareConfigs: a missing committed file is drift', () => {
  const result = compareConfigs('a\n', undefined);
  assert.equal(result.match, false);
  assert.match(result.reason, /does not exist/);
});

test('compareConfigs: a trailing difference is drift', () => {
  const result = compareConfigs('a\nb\n', 'a\n');
  assert.equal(result.match, false);
  assert.match(result.reason, /first difference at line 2/);
});

test('turns a block\'s rules off for its own ignores, right after the migrated override', () => {
  const eslintConfig = [
    { ignores: ['dist/**'] },
    { rules: { eqeqeq: 'error' } },
    { files: ['src/**/*.ts'], ignores: ['src/picker/**'], rules: { 'no-restricted-imports': ['error', { patterns: [] }] } },
    { files: ['**/*.entries.ts'], rules: { 'no-restricted-imports': 'error' } },
  ];
  const oxlintrc = {
    rules: { eqeqeq: 'error' },
    overrides: [
      { files: ['src/**/*.ts'], rules: { 'no-restricted-imports': ['error', { patterns: [] }] } },
      { files: ['**/*.entries.ts'], rules: { 'no-restricted-imports': 'error' } },
    ],
  };
  const { config, excluded } = excludeBlockIgnores(oxlintrc, eslintConfig);
  assert.deepEqual(config.overrides, [
    { files: ['src/**/*.ts'], rules: { 'no-restricted-imports': ['error', { patterns: [] }] } },
    { files: ['src/picker/**'], rules: { 'no-restricted-imports': 'off' } },
    { files: ['**/*.entries.ts'], rules: { 'no-restricted-imports': 'error' } },
  ]);
  assert.deepEqual(excluded, [{ override: 0, files: ['src/picker/**'] }]);
  assert.equal(oxlintrc.overrides.length, 2, 'input is not mutated');
});

test('refuses block ignores when an earlier block already enables the rule (off would hide it)', () => {
  const eslintConfig = [
    { rules: { 'no-restricted-imports': 'error' } },
    { files: ['src/**'], ignores: ['src/picker/**'], rules: { 'no-restricted-imports': 'warn' } },
  ];
  const oxlintrc = { rules: {}, overrides: [{ files: ['src/**'], rules: { 'no-restricted-imports': 'warn' } }] };
  assert.throws(() => excludeBlockIgnores(oxlintrc, eslintConfig), /no-restricted-imports.*earlier/);
});

test('refuses block ignores when no migrated override matches the block', () => {
  const eslintConfig = [{ files: ['src/**'], ignores: ['src/picker/**'], rules: { a: 'error' } }];
  assert.throws(() => excludeBlockIgnores({ rules: {}, overrides: [] }, eslintConfig), /src\/\*\*/);
});

test('leaves configs without block ignores untouched', () => {
  const eslintConfig = [{ ignores: ['dist/**'] }, { files: ['*.js'], rules: { a: 'off' } }];
  const oxlintrc = { rules: {}, overrides: [{ files: ['*.js'], rules: { a: 'off' } }] };
  assert.deepEqual(excludeBlockIgnores(oxlintrc, eslintConfig), { config: oxlintrc, excluded: [] });
});
