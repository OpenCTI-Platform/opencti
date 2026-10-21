import { createHash } from 'node:crypto';
import { ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_TOOL } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import type { CurationEvidence } from './curation-types';

export type TaxonomyFamily = 'actor' | 'software' | 'campaign';

const FAMILY_BY_TYPE: Record<string, TaxonomyFamily> = {
  [ENTITY_TYPE_INTRUSION_SET]: 'actor',
  [ENTITY_TYPE_THREAT_ACTOR_GROUP]: 'actor',
  [ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL]: 'actor',
  [ENTITY_TYPE_MALWARE]: 'software',
  [ENTITY_TYPE_TOOL]: 'software',
  [ENTITY_TYPE_CAMPAIGN]: 'campaign',
};

export const getTaxonomyFamily = (entityType: string): TaxonomyFamily | undefined => FAMILY_BY_TYPE[entityType];

// Words that vendors append to the same name ("Lazarus Group", "Clop Ransomware") without changing its meaning.
const FAMILY_STOP_WORDS: Record<TaxonomyFamily | 'default', Set<string>> = {
  actor: new Set(['group', 'team', 'gang', 'crew', 'actor', 'actors', 'threat', 'the', 'organization', 'organisation']),
  software: new Set(['ransomware', 'malware', 'trojan', 'backdoor', 'rat', 'stealer', 'infostealer', 'loader', 'dropper', 'botnet', 'worm', 'family', 'variant', 'tool', 'the', 'locker']),
  campaign: new Set(['campaign', 'operation', 'op', 'the']),
  default: new Set(['the']),
};

const LEET_MAP: Record<string, string[]> = {
  0: ['o'],
  1: ['i', 'l'],
  3: ['e'],
  4: ['a'],
  5: ['s'],
  7: ['t'],
  8: ['b'],
};

const isLetter = (char: string | undefined) => char !== undefined && /[a-z]/.test(char);

/**
 * Lowercase, strip diacritics and normalize symbols. Returns the list of word tokens.
 */
export const tokenizeName = (name: string): string[] => {
  return name
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/&/g, ' and ')
    .replace(/@/g, 'a')
    .replace(/\$/g, 's')
    .replace(/['\u2019`]/g, '')
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 0);
};

/**
 * Expand digits used as letters ("Cl0p", "B1ackCat") into their letter forms.
 * A digit is only considered a letter when it is surrounded by letters, so "APT28" or "LockBit 3.0" are untouched.
 */
export const expandLeetVariants = (token: string, maxVariants = 4): string[] => {
  let variants = [''];
  for (let index = 0; index < token.length; index += 1) {
    const char = token[index];
    const replacements = LEET_MAP[char];
    const surroundedByLetters = isLetter(token[index - 1]) && isLetter(token[index + 1]);
    if (replacements && surroundedByLetters) {
      const next: string[] = [];
      variants.forEach((variant) => replacements.forEach((replacement) => next.push(variant + replacement)));
      variants = next.slice(0, maxVariants);
    } else {
      variants = variants.map((variant) => variant + char);
    }
  }
  return variants;
};

const removeParentheticals = (name: string) => name.replace(/\([^)]*\)|\[[^\]]*\]/g, ' ');

export interface CanonicalForms {
  // Every word kept, separators removed ("Team TNT" -> "teamtnt").
  full: Set<string>;
  // Vendor suffixes and qualifiers removed ("Clop Ransomware (ELF)" -> "clop").
  stripped: Set<string>;
}

const MIN_CANONICAL_LENGTH = 3;

const isUsableCanonical = (value: string) => value.length >= MIN_CANONICAL_LENGTH && !/^\d+$/.test(value);

/**
 * Canonical forms of a single name, used to detect collisions across entities of the same family.
 */
export const canonicalizeName = (name: string, entityType?: string): CanonicalForms => {
  const family = entityType ? getTaxonomyFamily(entityType) : undefined;
  const stopWords = FAMILY_STOP_WORDS[family ?? 'default'];
  const full = new Set<string>();
  const stripped = new Set<string>();
  if (!name || typeof name !== 'string') {
    return { full, stripped };
  }
  const fullTokens = tokenizeName(name);
  const strippedTokens = tokenizeName(removeParentheticals(name)).filter((token) => !stopWords.has(token));
  const join = (tokens: string[]) => {
    const joined = tokens.join('');
    return expandLeetVariants(joined).filter(isUsableCanonical);
  };
  join(fullTokens).forEach((value) => full.add(value));
  join(strippedTokens).forEach((value) => {
    if (!full.has(value)) stripped.add(value);
  });
  return { full, stripped };
};

/**
 * Canonical forms of an entity: its name and every alias.
 */
export const canonicalizeEntityNames = (names: string[], entityType?: string): CanonicalForms => {
  const full = new Set<string>();
  const stripped = new Set<string>();
  names.forEach((name) => {
    const forms = canonicalizeName(name, entityType);
    forms.full.forEach((value) => full.add(value));
    forms.stripped.forEach((value) => stripped.add(value));
  });
  stripped.forEach((value) => {
    if (full.has(value)) stripped.delete(value);
  });
  return { full, stripped };
};

/**
 * Single comparable string for a name (first full variant), used for trigram similarity.
 */
export const comparableName = (name: string): string => tokenizeName(name).join(' ');

export const trigrams = (value: string): Set<string> => {
  const grams = new Set<string>();
  const padded = `  ${value} `;
  for (let index = 0; index < padded.length - 2; index += 1) {
    grams.add(padded.slice(index, index + 3));
  }
  return grams;
};

export const jaccard = <T>(left: Set<T> | T[], right: Set<T> | T[]): number => {
  const a = left instanceof Set ? left : new Set(left);
  const b = right instanceof Set ? right : new Set(right);
  if (a.size === 0 && b.size === 0) {
    return 0;
  }
  let intersection = 0;
  a.forEach((value) => {
    if (b.has(value)) intersection += 1;
  });
  return intersection / (a.size + b.size - intersection);
};

export const intersection = <T>(left: Set<T> | T[], right: Set<T> | T[]): T[] => {
  const b = right instanceof Set ? right : new Set(right);
  return [...(left instanceof Set ? left : new Set(left))].filter((value) => b.has(value));
};

/**
 * Trigram similarity (pg_trgm semantics: shared trigrams over the union) of two names.
 */
export const trigramSimilarity = (left: string, right: string): number => {
  const a = comparableName(left);
  const b = comparableName(right);
  if (a.length === 0 || b.length === 0) {
    return 0;
  }
  if (a === b) {
    return 1;
  }
  return jaccard(trigrams(a), trigrams(b));
};

export interface BestNameMatch {
  score: number;
  left: string;
  right: string;
}

/**
 * Best trigram similarity between any name/alias of the left entity and any name/alias of the right entity.
 * Names shorter than minLength characters are ignored (too short to be compared reliably).
 */
export const bestTrigramMatch = (leftNames: string[], rightNames: string[], minLength = 5): BestNameMatch | undefined => {
  let best: BestNameMatch | undefined;
  leftNames.forEach((left) => {
    if (comparableName(left).replace(/ /g, '').length < minLength) return;
    rightNames.forEach((right) => {
      if (comparableName(right).replace(/ /g, '').length < minLength) return;
      const score = trigramSimilarity(left, right);
      if (!best || score > best.score) {
        best = { score, left, right };
      }
    });
  });
  return best;
};

export const cosineSimilarity = (left: number[], right: number[]): number => {
  if (left.length === 0 || left.length !== right.length) {
    return 0;
  }
  let dot = 0;
  let normLeft = 0;
  let normRight = 0;
  for (let index = 0; index < left.length; index += 1) {
    dot += left[index] * right[index];
    normLeft += left[index] * left[index];
    normRight += right[index] * right[index];
  }
  if (normLeft === 0 || normRight === 0) {
    return 0;
  }
  return dot / (Math.sqrt(normLeft) * Math.sqrt(normRight));
};

// region description similarity (TF-IDF cosine, deterministic and explainable)
const DESCRIPTION_STOP_WORDS = new Set([
  'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'any', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'has', 'have', 'been',
  'this', 'that', 'with', 'from', 'they', 'their', 'them', 'were', 'which', 'when', 'what', 'will', 'into', 'than', 'then', 'there',
  'these', 'those', 'also', 'its', 'such', 'other', 'more', 'most', 'some', 'only', 'over', 'used', 'using', 'use', 'known', 'since',
  'group', 'actor', 'actors', 'threat', 'malware', 'tool', 'campaign', 'attack', 'attacks', 'activity', 'activities', 'based', 'reported',
  'organizations', 'organisation', 'organization', 'targets', 'targeted', 'targeting', 'used', 'operations', 'operation', 'least', 'first',
]);

export const tokenizeDescription = (text: string): string[] => {
  return tokenizeName(text ?? '').filter((token) => token.length >= 3 && !/^\d+$/.test(token) && !DESCRIPTION_STOP_WORDS.has(token));
};

export type SparseVector = Map<string, number>;

/**
 * Build L2-normalized TF-IDF vectors for a corpus of documents (one per entity of a given type).
 */
export const buildTfIdfVectors = (documents: Array<{ id: string; text: string }>): Map<string, SparseVector> => {
  const termFrequencies = new Map<string, Map<string, number>>();
  const documentFrequency = new Map<string, number>();
  documents.forEach(({ id, text }) => {
    const counts = new Map<string, number>();
    tokenizeDescription(text).forEach((token) => counts.set(token, (counts.get(token) ?? 0) + 1));
    if (counts.size === 0) return;
    termFrequencies.set(id, counts);
    counts.forEach((_, token) => documentFrequency.set(token, (documentFrequency.get(token) ?? 0) + 1));
  });
  const total = termFrequencies.size;
  const vectors = new Map<string, SparseVector>();
  termFrequencies.forEach((counts, id) => {
    const vector: SparseVector = new Map();
    let norm = 0;
    counts.forEach((count, token) => {
      const idf = Math.log((1 + total) / (1 + (documentFrequency.get(token) ?? 0))) + 1;
      const weight = (1 + Math.log(count)) * idf;
      vector.set(token, weight);
      norm += weight * weight;
    });
    const length = Math.sqrt(norm);
    vector.forEach((weight, token) => vector.set(token, weight / length));
    vectors.set(id, vector);
  });
  return vectors;
};

export const sparseCosine = (left: SparseVector, right: SparseVector): number => {
  const [small, large] = left.size <= right.size ? [left, right] : [right, left];
  let dot = 0;
  small.forEach((weight, token) => {
    const other = large.get(token);
    if (other !== undefined) dot += weight * other;
  });
  return dot;
};

export const topSharedTerms = (left: SparseVector, right: SparseVector, limit = 8): string[] => {
  const shared: Array<[string, number]> = [];
  left.forEach((weight, token) => {
    const other = right.get(token);
    if (other !== undefined) shared.push([token, weight * other]);
  });
  return shared.sort((a, b) => b[1] - a[1]).slice(0, limit).map(([token]) => token);
};
// endregion

export const clamp01 = (value: number) => Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));

export const roundScore = (value: number) => Math.round(clamp01(value) * 1000) / 1000;

/**
 * Combine evidence into one confidence.
 * Positive evidence (weight > 0) is combined with a noisy-OR: every independent signal raises the confidence without
 * ever exceeding 1. Negative evidence (weight < 0) then discounts the result multiplicatively.
 */
export const combineEvidence = (evidence: CurationEvidence[]): number => {
  let missing = 1;
  let discount = 1;
  let hasPositive = false;
  evidence.forEach((item) => {
    const contribution = clamp01(Math.abs(item.weight)) * clamp01(item.score);
    if (item.weight > 0) {
      hasPositive = true;
      missing *= (1 - contribution);
    } else if (item.weight < 0) {
      discount *= (1 - contribution);
    }
  });
  if (!hasPositive) {
    return 0;
  }
  return roundScore((1 - missing) * discount);
};

export const isInAmbiguousBand = (confidence: number, min: number, max: number) => confidence >= min && confidence < max;

export const buildProposalFingerprint = (kind: string, subjectIds: string[], discriminator?: string): string => {
  const base = `${kind}|${[...new Set(subjectIds)].sort().join(',')}|${discriminator ?? ''}`;
  return createHash('sha256').update(base).digest('hex');
};

/**
 * Pair fingerprint used to remember "distinct" decisions whatever the proposal kind that compared the pair.
 */
export const buildPairFingerprint = (subjectIds: string[]): string => buildProposalFingerprint('pair', subjectIds);
