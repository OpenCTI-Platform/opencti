import assert from 'node:assert/strict';
import { test } from 'node:test';
import { percentile, scoreChoice } from './metrics.ts';

test('scores accuracy, baseline, per-label precision and recall', () => {
  const score = scoreChoice([
    { expected: 'bug', predicted: 'bug', confidence: 0.95 },
    { expected: 'bug', predicted: 'bug', confidence: 0.85 },
    { expected: 'bug', predicted: 'feature', confidence: 0.55 },
    { expected: 'feature', predicted: 'feature', confidence: 0.9 },
  ]);
  assert.equal(score.total, 4);
  assert.equal(score.accuracy, 0.75);
  assert.equal(score.majorityBaseline, 0.75);
  assert.deepEqual(score.labels, [
    { label: 'bug', support: 3, precision: 1, recall: 2 / 3 },
    { label: 'feature', support: 1, precision: 0.5, recall: 1 },
  ]);
  assert.deepEqual(score.confusion, { bug: { bug: 2, feature: 1 }, feature: { feature: 1 } });
});

test('a higher threshold covers fewer issues and reports accuracy on those only', () => {
  const { thresholds } = scoreChoice([
    { expected: 'bug', predicted: 'bug', confidence: 0.95 },
    { expected: 'bug', predicted: 'feature', confidence: 0.55 },
  ]);
  assert.deepEqual(thresholds.find(({ threshold }) => threshold === 0.5), { threshold: 0.5, coverage: 1, accuracy: 0.5 });
  assert.deepEqual(thresholds.find(({ threshold }) => threshold === 0.9), { threshold: 0.9, coverage: 0.5, accuracy: 1 });
});

test('empty input and never-predicted labels yield null, not NaN', () => {
  const empty = scoreChoice([]);
  assert.equal(empty.accuracy, null);
  assert.equal(empty.majorityBaseline, null);
  assert.equal(empty.thresholds[0]?.accuracy, null);
  const [bug] = scoreChoice([{ expected: 'bug', predicted: 'feature', confidence: 1 }]).labels;
  assert.deepEqual(bug, { label: 'bug', support: 1, precision: null, recall: 0 });
});

test('percentile uses nearest rank', () => {
  assert.equal(percentile([40, 10, 30, 20], 50), 20);
  assert.equal(percentile([40, 10, 30, 20], 95), 40);
  assert.equal(percentile([], 50), null);
});
