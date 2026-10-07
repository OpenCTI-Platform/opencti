/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

// Deterministic Analysis of Competing Hypotheses (ACH) scoring.
//
// The agent proposes candidates and links evidence to them with a
// consistency in [-2, 2]; everything numeric is computed here, so the same
// matrix always yields the same scores, probabilities and labels.
//
// 1. Every cited piece of evidence gets a base weight: the weight of its
//    category times the reliability of its source (author reliability and
//    confidence of the evidence object).
// 2. Evidence that is equally consistent with every hypothesis does not help
//    to tell them apart (Heuer's diagnosticity): its weight is scaled by the
//    spread of its consistency across hypotheses.
// 3. A hypothesis is scored on its weighted support minus its weighted
//    inconsistency, inconsistency counting more (ACH seeks to refute).
// 4. Scores are normalized on an absolute evidence weight and become
//    probabilities through a softmax that always includes an implicit
//    "unknown actor" hypothesis scored 0, then are shrunk towards the uniform
//    distribution when the assessed evidence is light: a single weak
//    hypothesis is never reported as likely.
// 5. Probabilities map to fixed estimative-language labels.

import { InvestigationConfidenceLabel, InvestigationEvidenceCategory } from '../../generated/graphql';
import type { InvestigationEvidenceCell, InvestigationHypothesis } from './investigationRun-types';

export const ACH_CATEGORY_WEIGHTS: Record<InvestigationEvidenceCategory, number> = {
  [InvestigationEvidenceCategory.InfrastructureOverlap]: 1.0,
  [InvestigationEvidenceCategory.Tooling]: 0.9,
  [InvestigationEvidenceCategory.TtpOverlap]: 0.7,
  [InvestigationEvidenceCategory.SourceReliability]: 0.6,
  [InvestigationEvidenceCategory.Victimology]: 0.5,
  [InvestigationEvidenceCategory.Temporal]: 0.4,
  [InvestigationEvidenceCategory.LanguageTimezone]: 0.3,
};

// Admiralty-code reliability of the author of an evidence object.
const RELIABILITY_FACTORS: Record<string, number> = {
  A: 1.0,
  B: 0.9,
  C: 0.75,
  D: 0.6,
  E: 0.4,
  F: 0.5,
};
const UNKNOWN_RELIABILITY_FACTOR = 0.7;
const UNKNOWN_CONFIDENCE = 50;

// Inconsistent evidence weighs more than consistent evidence.
const INCONSISTENCY_PENALTY = 1.5;
// Floor of the diagnosticity multiplier: non-diagnostic evidence still counts a little.
const DIAGNOSTICITY_FLOOR = 0.25;
// Sharpness of the softmax over normalized scores.
const SOFTMAX_SHARPNESS = 4;
// Scores are normalized on an absolute scale: a matrix lighter than two
// strong, reliable and diagnostic items cannot fully support a hypothesis.
const REFERENCE_WEIGHT = 2;
// Effective evidence weight at which the matrix is trusted at 50%.
const EVIDENCE_PRIOR_WEIGHT = 1.5;

// Estimative language, from the most to the least likely (lower bounds).
export const ACH_CONFIDENCE_SCALE: Array<{ min: number; label: InvestigationConfidenceLabel }> = [
  { min: 0.95, label: InvestigationConfidenceLabel.AlmostCertain },
  { min: 0.8, label: InvestigationConfidenceLabel.VeryLikely },
  { min: 0.55, label: InvestigationConfidenceLabel.Likely },
  { min: 0.45, label: InvestigationConfidenceLabel.RoughlyEven },
  { min: 0.2, label: InvestigationConfidenceLabel.Unlikely },
  { min: 0.05, label: InvestigationConfidenceLabel.VeryUnlikely },
  { min: 0, label: InvestigationConfidenceLabel.Remote },
];

const CONFIDENCE_LABEL_TEXT: Record<InvestigationConfidenceLabel, string> = {
  [InvestigationConfidenceLabel.AlmostCertain]: 'almost certain',
  [InvestigationConfidenceLabel.VeryLikely]: 'very likely',
  [InvestigationConfidenceLabel.Likely]: 'likely',
  [InvestigationConfidenceLabel.RoughlyEven]: 'roughly even chance',
  [InvestigationConfidenceLabel.Unlikely]: 'unlikely',
  [InvestigationConfidenceLabel.VeryUnlikely]: 'very unlikely',
  [InvestigationConfidenceLabel.Remote]: 'remote chance',
};

const CATEGORY_TEXT: Record<InvestigationEvidenceCategory, string> = {
  [InvestigationEvidenceCategory.InfrastructureOverlap]: 'infrastructure overlap',
  [InvestigationEvidenceCategory.Tooling]: 'tooling',
  [InvestigationEvidenceCategory.TtpOverlap]: 'TTP overlap',
  [InvestigationEvidenceCategory.SourceReliability]: 'source reliability',
  [InvestigationEvidenceCategory.Victimology]: 'victimology',
  [InvestigationEvidenceCategory.Temporal]: 'temporal plausibility',
  [InvestigationEvidenceCategory.LanguageTimezone]: 'language and timezone',
};

export interface AchEvidenceMeta {
  id: string;
  standard_id?: string | null;
  entity_type?: string | null;
  name?: string | null;
  confidence?: number | null;
  author_reliability?: string | null;
}

export interface AchCellInput {
  evidence_id: string;
  category: InvestigationEvidenceCategory;
  consistency: number;
  rationale?: string | null;
}

export interface AchHypothesisInput {
  candidate_id: string;
  candidate_standard_id?: string | null;
  candidate_name?: string | null;
  candidate_type?: string | null;
  rationale?: string | null;
  evidence: AchCellInput[];
}

const round = (value: number, digits = 4) => {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

export const clampConsistency = (value: unknown): number => {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }
  return clamp(Math.round(numeric), -2, 2);
};

export const isEvidenceCategory = (value: unknown): value is InvestigationEvidenceCategory => {
  return typeof value === 'string' && Object.values(InvestigationEvidenceCategory).includes(value as InvestigationEvidenceCategory);
};

export const evidenceReliabilityFactor = (meta?: AchEvidenceMeta | null): number => {
  const code = (meta?.author_reliability ?? '').trim().charAt(0).toUpperCase();
  const reliability = RELIABILITY_FACTORS[code] ?? UNKNOWN_RELIABILITY_FACTOR;
  const confidence = typeof meta?.confidence === 'number' && Number.isFinite(meta.confidence)
    ? clamp(meta.confidence, 0, 100)
    : UNKNOWN_CONFIDENCE;
  // Confidence 0 halves the weight, confidence 100 keeps it whole.
  return round(reliability * (0.5 + confidence / 200));
};

export const confidenceLabelFor = (probability: number): InvestigationConfidenceLabel => {
  const value = Number.isFinite(probability) ? clamp(probability, 0, 1) : 0;
  const level = ACH_CONFIDENCE_SCALE.find(({ min }) => value >= min);
  return level ? level.label : InvestigationConfidenceLabel.Remote;
};

export const confidenceLabelText = (label: InvestigationConfidenceLabel) => CONFIDENCE_LABEL_TEXT[label];

export const evidenceCategoryText = (category: InvestigationEvidenceCategory) => CATEGORY_TEXT[category];

// The category an evidence item is weighted with: the one it is cited under
// most often, ties broken by the heaviest category, so a single evidence
// never carries two different weights across hypotheses.
const resolveEvidenceCategories = (hypotheses: AchHypothesisInput[]) => {
  const votes = new Map<string, Map<InvestigationEvidenceCategory, number>>();
  hypotheses.forEach((hypothesis) => {
    hypothesis.evidence.forEach((cell) => {
      const evidenceVotes = votes.get(cell.evidence_id) ?? new Map<InvestigationEvidenceCategory, number>();
      evidenceVotes.set(cell.category, (evidenceVotes.get(cell.category) ?? 0) + 1);
      votes.set(cell.evidence_id, evidenceVotes);
    });
  });
  const categories = new Map<string, InvestigationEvidenceCategory>();
  votes.forEach((evidenceVotes, evidenceId) => {
    const sorted = Array.from(evidenceVotes.entries()).sort((a, b) => {
      if (b[1] !== a[1]) return b[1] - a[1];
      return ACH_CATEGORY_WEIGHTS[b[0]] - ACH_CATEGORY_WEIGHTS[a[0]];
    });
    categories.set(evidenceId, sorted[0][0]);
  });
  return categories;
};

// One cell per evidence and hypothesis: the first citation wins.
const dedupeCells = (cells: AchCellInput[]) => {
  const seen = new Set<string>();
  return cells.filter((cell) => {
    if (seen.has(cell.evidence_id)) return false;
    seen.add(cell.evidence_id);
    return true;
  });
};

const describeCategories = (cells: InvestigationEvidenceCell[], positive: boolean) => {
  const byCategory = new Map<InvestigationEvidenceCategory, number>();
  cells
    .filter((cell) => (positive ? cell.consistency > 0 : cell.consistency < 0))
    .forEach((cell) => byCategory.set(cell.category, (byCategory.get(cell.category) ?? 0) + cell.weight * Math.abs(cell.consistency)));
  return Array.from(byCategory.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([category]) => {
      const count = cells.filter((cell) => cell.category === category && (positive ? cell.consistency > 0 : cell.consistency < 0)).length;
      return `${CATEGORY_TEXT[category]} (${count} item${count > 1 ? 's' : ''})`;
    });
};

const buildExplanation = (
  rank: number,
  total: number,
  probability: number,
  label: InvestigationConfidenceLabel,
  cells: InvestigationEvidenceCell[],
  assessedCount: number,
  evidenceCount: number,
  evidenceStrength: number,
) => {
  const parts = [`Ranked ${rank} of ${total} with a ${CONFIDENCE_LABEL_TEXT[label]} probability (${Math.round(probability * 100)}%).`];
  const support = describeCategories(cells, true);
  const contradiction = describeCategories(cells, false);
  parts.push(support.length > 0 ? `Supported by ${support.join(', ')}.` : 'No consistent evidence.');
  if (contradiction.length > 0) {
    parts.push(`Contradicted by ${contradiction.join(', ')}.`);
  }
  parts.push(`${assessedCount} of ${evidenceCount} evidence items assessed, evidence strength ${Math.round(evidenceStrength * 100)}%.`);
  return parts.join(' ');
};

/**
 * Score an ACH matrix. Pure and deterministic: the result only depends on
 * the matrix and on the metadata of the cited evidence.
 */
export const scoreAchMatrix = (
  hypothesesInput: AchHypothesisInput[],
  evidenceMeta: Map<string, AchEvidenceMeta> = new Map(),
): InvestigationHypothesis[] => {
  const hypotheses = hypothesesInput.map((hypothesis) => ({
    ...hypothesis,
    evidence: dedupeCells(hypothesis.evidence
      .filter((cell) => isEvidenceCategory(cell.category) && typeof cell.evidence_id === 'string' && cell.evidence_id.length > 0)
      .map((cell) => ({ ...cell, consistency: clampConsistency(cell.consistency) }))),
  }));
  if (hypotheses.length === 0) {
    return [];
  }
  const categories = resolveEvidenceCategories(hypotheses);
  const evidenceIds = Array.from(categories.keys());
  // Consistency of every (hypothesis, evidence) pair, 0 when not assessed.
  const consistencyOf = (hypothesisIndex: number, evidenceId: string) => {
    const cell = hypotheses[hypothesisIndex].evidence.find((c) => c.evidence_id === evidenceId);
    return cell ? cell.consistency : 0;
  };
  const effectiveWeights = new Map<string, { weight: number; diagnosticity: number }>();
  evidenceIds.forEach((evidenceId) => {
    const category = categories.get(evidenceId) as InvestigationEvidenceCategory;
    const baseWeight = ACH_CATEGORY_WEIGHTS[category] * evidenceReliabilityFactor(evidenceMeta.get(evidenceId));
    const values = hypotheses.map((_, index) => consistencyOf(index, evidenceId));
    // With a single hypothesis, diagnosticity is how far the evidence is from neutral.
    const diagnosticity = hypotheses.length === 1
      ? Math.abs(values[0]) / 2
      : (Math.max(...values) - Math.min(...values)) / 4;
    effectiveWeights.set(evidenceId, {
      weight: round(baseWeight * (DIAGNOSTICITY_FLOOR + (1 - DIAGNOSTICITY_FLOOR) * diagnosticity)),
      diagnosticity: round(diagnosticity),
    });
  });
  const totalWeight = evidenceIds.reduce((sum, evidenceId) => sum + (effectiveWeights.get(evidenceId)?.weight ?? 0), 0);
  const assessedIds = evidenceIds.filter((evidenceId) => hypotheses.some((_, index) => consistencyOf(index, evidenceId) !== 0));
  const evidenceStrength = totalWeight / (totalWeight + EVIDENCE_PRIOR_WEIGHT);
  const normalizationWeight = Math.max(totalWeight, REFERENCE_WEIGHT);

  const scored = hypotheses.map((hypothesis, index) => {
    let support = 0;
    let inconsistency = 0;
    const cells: InvestigationEvidenceCell[] = hypothesis.evidence.map((cell) => {
      const meta = evidenceMeta.get(cell.evidence_id);
      const { weight, diagnosticity } = effectiveWeights.get(cell.evidence_id) ?? { weight: 0, diagnosticity: 0 };
      if (cell.consistency > 0) support += weight * cell.consistency;
      if (cell.consistency < 0) inconsistency += weight * -cell.consistency;
      return {
        evidence_id: cell.evidence_id,
        evidence_standard_id: meta?.standard_id ?? null,
        evidence_type: meta?.entity_type ?? null,
        evidence_name: meta?.name ?? null,
        category: categories.get(cell.evidence_id) as InvestigationEvidenceCategory,
        consistency: cell.consistency,
        weight,
        diagnosticity,
        rationale: cell.rationale ?? null,
      };
    });
    const normalized = clamp((support - INCONSISTENCY_PENALTY * inconsistency) / (2 * normalizationWeight), -1, 1);
    return { hypothesis, index, cells, support, inconsistency, normalized };
  });

  // Softmax over the candidates plus the implicit "unknown actor" (score 0).
  const exponentials = scored.map(({ normalized }) => Math.exp(SOFTMAX_SHARPNESS * normalized));
  const unknownExponential = Math.exp(0);
  const denominator = exponentials.reduce((sum, value) => sum + value, unknownExponential);
  const uniform = 1 / (scored.length + 1);

  const withProbabilities = scored.map((entry, index) => {
    const raw = exponentials[index] / denominator;
    const probability = round(evidenceStrength * raw + (1 - evidenceStrength) * uniform);
    return { ...entry, probability };
  });
  const ordered = [...withProbabilities].sort((a, b) => {
    if (b.probability !== a.probability) return b.probability - a.probability;
    if (a.inconsistency !== b.inconsistency) return a.inconsistency - b.inconsistency;
    return (a.hypothesis.candidate_name ?? a.hypothesis.candidate_id).localeCompare(b.hypothesis.candidate_name ?? b.hypothesis.candidate_id);
  });
  return ordered.map((entry, position) => {
    const label = confidenceLabelFor(entry.probability);
    const assessed = entry.cells.some((cell) => cell.consistency !== 0);
    return {
      candidate_id: entry.hypothesis.candidate_id,
      candidate_standard_id: entry.hypothesis.candidate_standard_id ?? null,
      candidate_name: entry.hypothesis.candidate_name ?? null,
      candidate_type: entry.hypothesis.candidate_type ?? null,
      rationale: entry.hypothesis.rationale ?? null,
      evidence: entry.cells,
      rank: position + 1,
      score: round(entry.normalized),
      inconsistency: round(entry.inconsistency),
      probability: entry.probability,
      confidence: assessed ? Math.round(entry.probability * 100) : null,
      confidence_label: assessed ? label : null,
      explanation: buildExplanation(
        position + 1,
        ordered.length,
        entry.probability,
        label,
        entry.cells,
        assessedIds.length,
        evidenceIds.length,
        evidenceStrength,
      ),
    };
  });
};
