import type { Classifier, TriageDecision } from './classifier.ts';
import { groundTruth, type GroundTruth, type Issue } from './issue.ts';
import { percentile, scoreChoice, type ChoiceScore, type Sample } from './metrics.ts';

export interface Prediction {
  issue: Pick<Issue, 'number' | 'title'>;
  expected: GroundTruth;
  decision: TriageDecision;
}

export interface Failure {
  number: number;
  error: string;
}

export interface Evaluation {
  model: string | null;
  /** Issues with at least one unambiguous human label, i.e. worth a call. */
  evaluated: number;
  /** Issues left out because no human label could serve as ground truth. */
  skipped: number;
  failures: Failure[];
  type: ChoiceScore;
  area: ChoiceScore;
  latencyMs: { p50: number | null; p95: number | null };
  inputTokens: number;
  predictions: Prediction[];
}

/** Runs `task` over `items` with at most `limit` in flight, keeping input order. */
const mapWithConcurrency = async <T, R>(items: readonly T[], limit: number, task: (item: T) => Promise<R>): Promise<R[]> => {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await task(items[index] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
};

export const runEvaluation = async (issues: readonly Issue[], classifier: Classifier, concurrency = 8): Promise<Evaluation> => {
  const labelled = issues
    .map((issue) => ({ issue, expected: groundTruth(issue) }))
    .filter(({ expected }) => expected.type !== undefined || expected.area !== undefined);

  const failures: Failure[] = [];
  const outcomes = await mapWithConcurrency(labelled, concurrency, async ({ issue, expected }): Promise<Prediction | undefined> => {
    try {
      return { issue: { number: issue.number, title: issue.title }, expected, decision: await classifier.classify(issue) };
    } catch (error) {
      // One failed call must not cost the whole run; it is reported instead.
      failures.push({ number: issue.number, error: error instanceof Error ? error.message : String(error) });
      return undefined;
    }
  });
  const predictions = outcomes.filter((outcome) => outcome !== undefined);

  const samples = (key: 'type' | 'area'): Sample[] =>
    predictions.flatMap(({ expected, decision }) => {
      const label = expected[key];
      return label === undefined ? [] : [{ expected: label, predicted: decision[key].label, confidence: decision[key].confidence }];
    });
  const latencies = predictions.map(({ decision }) => decision.latencyMs);

  return {
    model: predictions[0]?.decision.model ?? null,
    evaluated: labelled.length,
    skipped: issues.length - labelled.length,
    failures,
    type: scoreChoice(samples('type')),
    area: scoreChoice(samples('area')),
    latencyMs: { p50: percentile(latencies, 50), p95: percentile(latencies, 95) },
    inputTokens: predictions.reduce((sum, { decision }) => sum + (decision.inputTokens ?? 0), 0),
    predictions,
  };
};
