import type { ChoiceDecision, TriageDecision } from './classifier.ts';
import type { Evaluation } from './evaluation.ts';
import type { ChoiceScore } from './metrics.ts';

const percent = (value: number | null) => (value === null ? 'n/a' : `${(value * 100).toFixed(1)}%`);
const millis = (value: number | null) => (value === null ? 'n/a' : `${Math.round(value)} ms`);

const renderScore = (title: string, score: ChoiceScore): string => {
  if (score.total === 0) return `## ${title}\n\nNo issue with a usable human label.\n`;
  const wrong = Object.entries(score.confusion)
    .flatMap(([expected, row]) => Object.entries(row).map(([predicted, count]) => ({ expected, predicted, count })))
    .filter(({ expected, predicted }) => expected !== predicted)
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
  return [
    `## ${title}`,
    '',
    `Accuracy **${percent(score.accuracy)}** on ${score.total} issues (always answering the most frequent label: ${percent(score.majorityBaseline)}).`,
    '',
    '| Label | Issues | Precision | Recall |',
    '|---|---:|---:|---:|',
    ...score.labels.map(({ label, support, precision, recall }) => `| ${label} | ${support} | ${percent(precision)} | ${percent(recall)} |`),
    '',
    'Auto-labelling only above a confidence threshold:',
    '',
    '| Confidence ≥ | Issues covered | Accuracy on those |',
    '|---:|---:|---:|',
    ...score.thresholds.map(({ threshold, coverage, accuracy }) => `| ${threshold} | ${percent(coverage)} | ${percent(accuracy)} |`),
    '',
    ...(wrong.length === 0
      ? []
      : ['Most frequent mistakes:', '', '| Human label | Model answer | Count |', '|---|---|---:|', ...wrong.map(({ expected, predicted, count }) => `| ${expected} | ${predicted} | ${count} |`), '']),
  ].join('\n');
};

export const renderEvaluation = (evaluation: Evaluation, provider: string): string =>
  [
    `# Issue triage — evaluation (${provider})`,
    '',
    `Model \`${evaluation.model ?? 'n/a'}\` · ${evaluation.evaluated} issues evaluated · ${evaluation.skipped} skipped (no usable human label) · ${evaluation.failures.length} failed calls`,
    '',
    `Latency p50 ${millis(evaluation.latencyMs.p50)}, p95 ${millis(evaluation.latencyMs.p95)} · ${evaluation.inputTokens} input tokens`,
    '',
    renderScore('Type', evaluation.type),
    renderScore('Area', evaluation.area),
    ...(evaluation.failures.length === 0
      ? []
      : ['## Failed calls', '', ...evaluation.failures.map(({ number, error }) => `- #${number}: ${error}`), '']),
  ].join('\n');

const renderChoice = <L extends string>(name: string, decision: ChoiceDecision<L>): string => {
  const runnerUp = (Object.entries(decision.probabilities) as [L, number | undefined][])
    .filter((entry): entry is [L, number] => entry[1] !== undefined)
    .filter(([label]) => label !== decision.label)
    .sort((a, b) => b[1] - a[1])[0];
  return `| ${name} | \`${decision.label}\` | ${percent(decision.confidence)} | ${runnerUp ? `\`${runnerUp[0]}\` (${percent(runnerUp[1])})` : ''} |`;
};

export const renderTriage = (issueNumber: number, decision: TriageDecision): string =>
  [
    `### Suggested triage for #${issueNumber} (shadow mode)`,
    '',
    '| Decision | Suggestion | Confidence | Runner-up |',
    '|---|---|---:|---|',
    renderChoice('Type', decision.type),
    renderChoice('Area', decision.area),
    `| Needs more info | ${decision.needsMoreInfo >= 0.5 ? 'yes' : 'no'} | ${percent(decision.needsMoreInfo)} probability of yes | |`,
    '',
    `_Suggestion only, no label was applied. Model \`${decision.model}\`, ${millis(decision.latencyMs)}._`,
    '',
  ].join('\n');
