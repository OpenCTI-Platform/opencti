import { createJevClassifier, type Classifier } from './classifier.ts';
import type { PrepareOptions } from './issue.ts';
import { createLlmClassifier } from './llm-classifier.ts';

export type Provider = 'jev' | 'llm';

type Env = Readonly<Record<string, string | undefined>>;

/** TRIAGE_PROVIDER when set, otherwise whichever provider is configured; Jev wins a tie. */
export const resolveProvider = (env: Env = process.env): Provider | undefined => {
  const explicit = env.TRIAGE_PROVIDER;
  if (explicit === 'jev' || explicit === 'llm') return explicit;
  if (explicit) throw new Error(`TRIAGE_PROVIDER must be "jev" or "llm", got "${explicit}"`);
  if (env.TYPESAFE_API_KEY) return 'jev';
  if (env.LLM_MODEL) return 'llm';
  return undefined;
};

export const createClassifier = (provider: Provider, options: PrepareOptions = {}, env: Env = process.env): Classifier => {
  if (provider === 'jev') return createJevClassifier({ ...options, model: env.TRIAGE_MODEL || undefined });
  if (!env.LLM_MODEL) throw new Error('LLM_MODEL is required for the "llm" provider');
  return createLlmClassifier({
    ...options,
    // Ollama's default address: the zero-setup way to run an open-source model.
    baseUrl: env.LLM_BASE_URL || 'http://localhost:11434/v1',
    model: env.LLM_MODEL,
    apiKey: env.LLM_API_KEY || undefined,
  });
};
