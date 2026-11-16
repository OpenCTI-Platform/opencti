import assert from 'node:assert/strict';
import { test } from 'node:test';
import { groundTruth, toState, type Issue } from './issue.ts';

const issue = (overrides: Partial<Issue> = {}): Issue => ({ number: 1, title: 'fix(export): csv is empty', body: 'Steps', labels: [], ...overrides });

test('the title prefix is stripped unless asked otherwise', () => {
  assert.equal(toState(issue()).title, 'csv is empty');
  assert.equal(toState(issue({ title: 'feat(api)!: drop v1' })).title, 'drop v1');
  assert.equal(toState(issue({ title: 'Export is broken' })).title, 'Export is broken');
  assert.equal(toState(issue(), { keepTitlePrefix: true }).title, 'fix(export): csv is empty');
});

test('template comments are removed and long bodies are cut', () => {
  assert.equal(toState(issue({ body: '## Description\n<!-- describe\nthe bug -->\nIt crashes' })).body, '## Description\n\nIt crashes');
  assert.equal(toState(issue({ body: 'x'.repeat(20000) })).body.length, 8000);
});

test('labels are never part of what the model sees', () => {
  assert.deepEqual(Object.keys(toState(issue({ labels: ['bug'] }))), ['title', 'body']);
});

test('ground truth keeps only unambiguous human labels', () => {
  assert.deepEqual(groundTruth(issue({ labels: ['bug', 'solved', 'export'] })), { type: 'bug', area: 'export' });
  assert.deepEqual(groundTruth(issue({ labels: ['bug', 'feature', 'rbac', 'iam'] })), { type: undefined, area: undefined });
  assert.deepEqual(groundTruth(issue({ labels: ['filigran team'] })), { type: undefined, area: undefined });
});
