import { AREA_LABELS, TYPE_LABELS, type AreaLabel, type TypeLabel } from './taxonomy.ts';

export interface Issue {
  number: number;
  title: string;
  body: string;
  labels: string[];
}

/** Longest body sent to the model; issues with pasted logs can be very long. */
const MAX_BODY_CHARS = 8000;

/** `fix(scope)!: ` and friends, as mandated by .github/LABELS.md. */
const CONVENTIONAL_PREFIX = /^\s*(feat|fix|chore|docs|style|refactor|perf|test|build|ci|revert)(\([^)]*\))?!?:\s*/i;

export interface PrepareOptions {
  /**
   * Keep the Conventional Commits prefix of the title. Off by default: the
   * prefix states the type and the scope outright, so leaving it in measures
   * how well the model reads a prefix, not how well it triages.
   */
  keepTitlePrefix?: boolean;
}

/** What the model sees of an issue. Labels never go in: they are the answer. */
export const toState = (issue: Issue, { keepTitlePrefix = false }: PrepareOptions = {}) => {
  const title = keepTitlePrefix ? issue.title : issue.title.replace(CONVENTIONAL_PREFIX, '');
  const body = issue.body
    .replace(/<!--[\s\S]*?-->/g, '') // template instructions left in by the author
    .trim()
    .slice(0, MAX_BODY_CHARS);
  return { title: title.trim(), body };
};

const only = <L extends string>(candidates: readonly L[], labels: readonly string[]): L | undefined => {
  const found = candidates.filter((candidate) => labels.includes(candidate));
  return found.length === 1 ? found[0] : undefined;
};

export interface GroundTruth {
  type?: TypeLabel;
  area?: AreaLabel;
}

/**
 * The labels a human settled on, where they are unambiguous. An issue with no
 * area label is left out of the area score rather than counted as `none`:
 * most issues are simply never given an area.
 */
export const groundTruth = (issue: Issue): GroundTruth => ({
  type: only(TYPE_LABELS, issue.labels),
  area: only(AREA_LABELS, issue.labels),
});
