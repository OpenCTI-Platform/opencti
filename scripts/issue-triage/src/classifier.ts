import { choice, noul, TypeSafeClient } from '@typesafe-ai/sdk';
import { toState, type Issue, type PrepareOptions } from './issue.ts';
import { AREA_CRITERIA, TYPE_CRITERIA, type AreaLabel, type TypeLabel } from './taxonomy.ts';

export interface ChoiceDecision<L extends string> {
  label: L;
  confidence: number;
  /** Per-label probabilities; a provider that reports none leaves labels out. */
  probabilities: Readonly<Partial<Record<L, number>>>;
}

export interface TriageDecision {
  type: ChoiceDecision<TypeLabel>;
  area: ChoiceDecision<AreaLabel>;
  /** Probability that the issue cannot be acted on without asking the author for more. */
  needsMoreInfo: number;
  model: string;
  inputTokens: number | null;
  latencyMs: number;
}

/** The seam the evaluation and the tests plug into; Jev is one implementation. */
export interface Classifier {
  classify(issue: Issue): Promise<TriageDecision>;
}

/** Wording shared by every provider, so they are compared on the same questions. */
export const PROMPTS = {
  type: 'What kind of issue is this?',
  area: 'Which area of the OpenCTI platform does this issue concern?',
  needsMoreInfo: 'Is information missing that a maintainer needs before acting on this issue?',
  needsMoreInfoYes: 'A bug without a way to reproduce it, the observed behavior or the version; or a request too vague to scope.',
  needsMoreInfoNo: 'A maintainer can reproduce the bug or scope the request from what is written.',
} as const;

const QUESTIONS = {
  type: choice(PROMPTS.type, TYPE_CRITERIA),
  area: choice(PROMPTS.area, AREA_CRITERIA),
  needsMoreInfo: noul(PROMPTS.needsMoreInfo, { true: PROMPTS.needsMoreInfoYes, false: PROMPTS.needsMoreInfoNo }),
};

export interface JevClassifierOptions extends PrepareOptions {
  client?: TypeSafeClient;
  /** Pin a release (e.g. `jev-1.13.0`) for a comparable evaluation; `jev-latest` moves. */
  model?: string;
}

/** Reads TYPESAFE_API_KEY from the environment unless a client is injected. */
export const createJevClassifier = (options: JevClassifierOptions = {}): Classifier => {
  const client = options.client ?? new TypeSafeClient();
  return {
    async classify(issue) {
      const startedAt = performance.now();
      const { answers, model, usage } = await client.systemOne({
        state: toState(issue, options),
        questions: QUESTIONS,
        model: options.model,
      });
      return {
        type: { label: answers.type.choice, confidence: answers.type.confidence, probabilities: answers.type.probabilities },
        area: { label: answers.area.choice, confidence: answers.area.confidence, probabilities: answers.area.probabilities },
        needsMoreInfo: answers.needsMoreInfo.noul,
        model,
        inputTokens: usage.input_tokens,
        latencyMs: performance.now() - startedAt,
      };
    },
  };
};
