import test from 'node:test';
import assert from 'node:assert/strict';
import { anchorOverrideGlobs, rootAnchorGlob, serializeConfig } from '../oxlintrc.mjs';

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
