export interface Sample {
  expected: string;
  predicted: string;
  confidence: number;
}

export interface LabelScore {
  label: string;
  /** Issues a human gave this label. */
  support: number;
  /** Of the issues predicted with this label, the share that were right; null when never predicted. */
  precision: number | null;
  /** Of the issues carrying this label, the share that were found; null when support is 0. */
  recall: number | null;
}

export interface ThresholdScore {
  threshold: number;
  /** Share of issues whose confidence reaches the threshold, i.e. that would be auto-labelled. */
  coverage: number;
  /** Accuracy among those; null when nothing reaches the threshold. */
  accuracy: number | null;
}

export interface ChoiceScore {
  total: number;
  accuracy: number | null;
  /** Accuracy of always answering the most frequent label: the number to beat. */
  majorityBaseline: number | null;
  labels: LabelScore[];
  thresholds: ThresholdScore[];
  /** confusion[expected][predicted] = count. */
  confusion: Record<string, Record<string, number>>;
}

export const THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95];

const ratio = (part: number, whole: number) => (whole === 0 ? null : part / whole);

export const scoreChoice = (samples: readonly Sample[]): ChoiceScore => {
  const confusion: ChoiceScore['confusion'] = {};
  const expectedCount = new Map<string, number>();
  const predictedCount = new Map<string, number>();
  const hitCount = new Map<string, number>();
  const bump = (map: Map<string, number>, key: string) => map.set(key, (map.get(key) ?? 0) + 1);

  for (const { expected, predicted } of samples) {
    bump(expectedCount, expected);
    bump(predictedCount, predicted);
    if (expected === predicted) bump(hitCount, expected);
    const row = (confusion[expected] ??= {});
    row[predicted] = (row[predicted] ?? 0) + 1;
  }

  const allLabels = [...new Set([...expectedCount.keys(), ...predictedCount.keys()])].sort();
  const hits = samples.filter((sample) => sample.expected === sample.predicted).length;

  return {
    total: samples.length,
    accuracy: ratio(hits, samples.length),
    majorityBaseline: ratio(Math.max(0, ...expectedCount.values()), samples.length),
    labels: allLabels.map((label) => ({
      label,
      support: expectedCount.get(label) ?? 0,
      precision: ratio(hitCount.get(label) ?? 0, predictedCount.get(label) ?? 0),
      recall: ratio(hitCount.get(label) ?? 0, expectedCount.get(label) ?? 0),
    })),
    thresholds: THRESHOLDS.map((threshold) => {
      const covered = samples.filter((sample) => sample.confidence >= threshold);
      return {
        threshold,
        coverage: ratio(covered.length, samples.length) ?? 0,
        accuracy: ratio(covered.filter((sample) => sample.expected === sample.predicted).length, covered.length),
      };
    }),
    confusion,
  };
};

/** Nearest-rank percentile; null on an empty list. */
export const percentile = (values: readonly number[], p: number): number | null => {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))] ?? null;
};
