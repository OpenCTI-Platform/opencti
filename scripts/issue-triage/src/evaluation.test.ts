import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Classifier, TriageDecision } from './classifier.ts';
import { runEvaluation } from './evaluation.ts';
import type { Issue } from './issue.ts';
import { renderEvaluation, renderTriage } from './report.ts';

const decision = (type: TriageDecision['type']['label'], area: TriageDecision['area']['label']): TriageDecision => ({
  type: { label: type, confidence: 0.9, probabilities: { [type]: 0.9 } },
  area: { label: area, confidence: 0.6, probabilities: { [area]: 0.6, none: 0.3 } },
  needsMoreInfo: 0.2,
  model: 'fake-1',
  inputTokens: 100,
  latencyMs: 12,
});

const issues: Issue[] = [
  { number: 1, title: 'csv export is empty', body: '', labels: ['bug', 'export'] },
  { number: 2, title: 'add a widget', body: '', labels: ['feature'] },
  { number: 3, title: 'unlabelled', body: '', labels: ['filigran team'] },
  { number: 4, title: 'boom', body: '', labels: ['bug'] },
];

const classifier: Classifier = {
  async classify(issue) {
    if (issue.number === 4) throw new Error('rate limited');
    return issue.number === 1 ? decision('bug', 'ingestion') : decision('feature', 'dashboards');
  },
};

test('scores only human-labelled issues and reports failed calls', async () => {
  const called: number[] = [];
  const evaluation = await runEvaluation(issues, { classify: (issue) => (called.push(issue.number), classifier.classify(issue)) }, 2);

  assert.deepEqual(called.sort(), [1, 2, 4], 'the unlabelled issue costs no call');
  assert.equal(evaluation.evaluated, 3);
  assert.equal(evaluation.skipped, 1);
  assert.deepEqual(evaluation.failures, [{ number: 4, error: 'rate limited' }]);
  assert.equal(evaluation.type.total, 2);
  assert.equal(evaluation.type.accuracy, 1);
  assert.equal(evaluation.area.total, 1, 'an issue without an area label is not scored on area');
  assert.equal(evaluation.area.accuracy, 0);
  assert.equal(evaluation.inputTokens, 200);
  assert.equal(evaluation.model, 'fake-1');

  const report = renderEvaluation(evaluation, 'fake');
  assert.match(report, /Accuracy \*\*100\.0%\*\* on 2 issues/);
  assert.match(report, /\| export \| ingestion \| 1 \|/);
  assert.match(report, /- #4: rate limited/);
});

test('the triage summary shows the suggestion and the runner-up', () => {
  const summary = renderTriage(42, decision('bug', 'export'));
  assert.match(summary, /\| Type \| `bug` \| 90\.0% \|  \|/);
  assert.match(summary, /\| Area \| `export` \| 60\.0% \| `none` \(30\.0%\) \|/);
  assert.match(summary, /\| Needs more info \| no \|/);
});
