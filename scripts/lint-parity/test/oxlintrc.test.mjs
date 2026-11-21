import test from 'node:test';
import assert from 'node:assert/strict';
import { anchorOverrideGlobs, compareConfigs, rootAnchorGlob, serializeConfig } from '../oxlintrc.mjs';

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
