import { describe, expect, it } from 'vitest';
import { InvestigationConfidenceLabel, InvestigationEvidenceCategory } from '../../../../src/generated/graphql';
import {
  ACH_CATEGORY_WEIGHTS,
  type AchEvidenceMeta,
  type AchHypothesisInput,
  clampConsistency,
  confidenceLabelFor,
  evidenceReliabilityFactor,
  scoreAchMatrix,
} from '../../../../src/modules/investigationRun/investigationRun-ach';

const C = InvestigationEvidenceCategory;

// Two competing intrusion sets for a spearphishing incident.
const evidenceMeta = new Map<string, AchEvidenceMeta>([
  ['ip-c2', { id: 'ip-c2', name: '185.12.4.2', confidence: 90, author_reliability: 'A' }],
  ['malware-x', { id: 'malware-x', name: 'X-Agent', confidence: 80, author_reliability: 'B' }],
  ['ttp-phishing', { id: 'ttp-phishing', name: 'T1566.001', confidence: 70, author_reliability: 'C' }],
  ['sector-energy', { id: 'sector-energy', name: 'Energy', confidence: 60, author_reliability: 'B' }],
  ['timing', { id: 'timing', name: 'Working hours UTC+3', confidence: 50 }],
  ['language', { id: 'language', name: 'Cyrillic strings', confidence: 40, author_reliability: 'E' }],
]);

const apt28: AchHypothesisInput = {
  candidate_id: 'apt28',
  candidate_name: 'APT28',
  candidate_type: 'Intrusion-Set',
  evidence: [
    { evidence_id: 'ip-c2', category: C.InfrastructureOverlap, consistency: 2 },
    { evidence_id: 'malware-x', category: C.Tooling, consistency: 1 },
    { evidence_id: 'ttp-phishing', category: C.TtpOverlap, consistency: 1 },
    { evidence_id: 'sector-energy', category: C.Victimology, consistency: -1 },
    { evidence_id: 'timing', category: C.Temporal, consistency: 1 },
  ],
};

const apt29: AchHypothesisInput = {
  candidate_id: 'apt29',
  candidate_name: 'APT29',
  candidate_type: 'Intrusion-Set',
  evidence: [
    { evidence_id: 'ip-c2', category: C.InfrastructureOverlap, consistency: -2 },
    { evidence_id: 'malware-x', category: C.Tooling, consistency: 1 },
    { evidence_id: 'ttp-phishing', category: C.TtpOverlap, consistency: 1 },
    { evidence_id: 'sector-energy', category: C.Victimology, consistency: 1 },
    { evidence_id: 'language', category: C.LanguageTimezone, consistency: 1 },
  ],
};

describe('Case Autopilot ACH scoring', () => {
  it('ranks the hypothesis supported by diagnostic evidence first', () => {
    const [first, second] = scoreAchMatrix([apt29, apt28], evidenceMeta);
    expect(first.candidate_id).toBe('apt28');
    expect(first.rank).toBe(1);
    expect(second.candidate_id).toBe('apt29');
    expect(second.rank).toBe(2);
    expect(first.probability).toBeGreaterThan(second.probability);
    expect(first.score).toBeGreaterThan(second.score);
    expect(second.inconsistency).toBeGreaterThan(first.inconsistency);
  });

  it('gives no confidence to a hypothesis no evidence assessed, never a defaulted one', () => {
    const unassessed: AchHypothesisInput = {
      candidate_id: 'fin7',
      candidate_name: 'FIN7',
      candidate_type: 'Intrusion-Set',
      evidence: [{ evidence_id: 'timing', category: C.Temporal, consistency: 0 }],
    };
    const scored = scoreAchMatrix([apt28, unassessed], evidenceMeta);
    const fin7 = scored.find((hypothesis) => hypothesis.candidate_id === 'fin7');
    const leading = scored.find((hypothesis) => hypothesis.candidate_id === 'apt28');
    expect(fin7?.confidence).toBeNull();
    expect(fin7?.confidence_label).toBeNull();
    expect(fin7?.probability).toBeGreaterThan(0);
    expect(leading?.confidence).toBe(Math.round((leading?.probability ?? 0) * 100));
    expect(leading?.confidence_label).not.toBeNull();
  });

  it('is deterministic', () => {
    const once = scoreAchMatrix([apt28, apt29], evidenceMeta);
    const twice = scoreAchMatrix([apt28, apt29], evidenceMeta);
    expect(twice).toEqual(once);
  });

  it('keeps probability mass for an unknown actor', () => {
    const scored = scoreAchMatrix([apt28, apt29], evidenceMeta);
    const total = scored.reduce((sum, hypothesis) => sum + hypothesis.probability, 0);
    expect(total).toBeLessThan(1);
    expect(total).toBeGreaterThan(0.5);
  });

  it('gives no diagnostic value to evidence consistent with every hypothesis', () => {
    const [first] = scoreAchMatrix([apt28, apt29], evidenceMeta);
    const tooling = first.evidence.find((cell) => cell.evidence_id === 'malware-x');
    const infrastructure = first.evidence.find((cell) => cell.evidence_id === 'ip-c2');
    expect(tooling?.diagnosticity).toBe(0);
    expect(infrastructure?.diagnosticity).toBe(1);
    expect((infrastructure?.weight ?? 0)).toBeGreaterThan(tooling?.weight ?? 0);
  });

  it('lowers a hypothesis when contradictory evidence is added', () => {
    const [baseline] = scoreAchMatrix([apt28, apt29], evidenceMeta).filter((h) => h.candidate_id === 'apt28');
    const contradicted: AchHypothesisInput = {
      ...apt28,
      evidence: [...apt28.evidence, { evidence_id: 'language', category: C.LanguageTimezone, consistency: -2 }],
    };
    const [after] = scoreAchMatrix([contradicted, apt29], evidenceMeta).filter((h) => h.candidate_id === 'apt28');
    expect(after.probability).toBeLessThan(baseline.probability);
    expect(after.inconsistency).toBeGreaterThan(baseline.inconsistency);
  });

  it('never reports a single weakly supported hypothesis as likely', () => {
    const lonely: AchHypothesisInput = {
      candidate_id: 'apt28',
      candidate_name: 'APT28',
      evidence: [{ evidence_id: 'timing', category: C.Temporal, consistency: 1 }],
    };
    const [scored] = scoreAchMatrix([lonely], evidenceMeta);
    expect(scored.probability).toBeLessThan(0.55);
    expect([InvestigationConfidenceLabel.RoughlyEven, InvestigationConfidenceLabel.Unlikely]).toContain(scored.confidence_label);
  });

  it('reaches a high confidence with abundant, consistent and diagnostic evidence', () => {
    const ids = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
    const meta = new Map<string, AchEvidenceMeta>(ids.map((id) => [id, { id, confidence: 100, author_reliability: 'A' }]));
    const strong: AchHypothesisInput = { candidate_id: 'h1', evidence: ids.map((id) => ({ evidence_id: id, category: C.InfrastructureOverlap, consistency: 2 })) };
    const weak: AchHypothesisInput = { candidate_id: 'h2', evidence: ids.map((id) => ({ evidence_id: id, category: C.InfrastructureOverlap, consistency: -2 })) };
    const [first] = scoreAchMatrix([strong, weak], meta);
    expect(first.candidate_id).toBe('h1');
    expect(first.probability).toBeGreaterThanOrEqual(0.55);
    expect([InvestigationConfidenceLabel.Likely, InvestigationConfidenceLabel.VeryLikely, InvestigationConfidenceLabel.AlmostCertain]).toContain(first.confidence_label);
  });

  it('clamps consistency, drops invalid cells and keeps the first citation of an evidence', () => {
    const messy: AchHypothesisInput = {
      candidate_id: 'apt28',
      evidence: [
        { evidence_id: 'ip-c2', category: C.InfrastructureOverlap, consistency: 7 },
        { evidence_id: 'ip-c2', category: C.InfrastructureOverlap, consistency: -2 },
        { evidence_id: 'bad', category: 'made_up' as InvestigationEvidenceCategory, consistency: 2 },
        { evidence_id: '', category: C.Tooling, consistency: 1 },
      ],
    };
    const [scored] = scoreAchMatrix([messy], evidenceMeta);
    expect(scored.evidence).toHaveLength(1);
    expect(scored.evidence[0].consistency).toBe(2);
  });

  it('uses one category per evidence across hypotheses', () => {
    const h1: AchHypothesisInput = { candidate_id: 'h1', evidence: [{ evidence_id: 'x', category: C.Temporal, consistency: 1 }] };
    const h2: AchHypothesisInput = { candidate_id: 'h2', evidence: [{ evidence_id: 'x', category: C.InfrastructureOverlap, consistency: -1 }] };
    const scored = scoreAchMatrix([h1, h2], new Map());
    const categories = scored.flatMap((hypothesis) => hypothesis.evidence.map((cell) => cell.category));
    expect(new Set(categories).size).toBe(1);
    // Tie on votes: the heaviest category wins.
    expect(categories[0]).toBe(C.InfrastructureOverlap);
  });

  it('explains the result with the supporting and contradicting categories', () => {
    const [first] = scoreAchMatrix([apt28, apt29], evidenceMeta);
    expect(first.explanation).toContain('Ranked 1 of 2');
    expect(first.explanation).toContain('infrastructure overlap');
    expect(first.explanation).toContain('Contradicted by victimology');
  });

  it('returns nothing for an empty matrix', () => {
    expect(scoreAchMatrix([], evidenceMeta)).toEqual([]);
  });
});

describe('Case Autopilot ACH helpers', () => {
  it('maps probabilities on the fixed estimative scale', () => {
    expect(confidenceLabelFor(0.97)).toBe(InvestigationConfidenceLabel.AlmostCertain);
    expect(confidenceLabelFor(0.85)).toBe(InvestigationConfidenceLabel.VeryLikely);
    expect(confidenceLabelFor(0.6)).toBe(InvestigationConfidenceLabel.Likely);
    expect(confidenceLabelFor(0.5)).toBe(InvestigationConfidenceLabel.RoughlyEven);
    expect(confidenceLabelFor(0.3)).toBe(InvestigationConfidenceLabel.Unlikely);
    expect(confidenceLabelFor(0.1)).toBe(InvestigationConfidenceLabel.VeryUnlikely);
    expect(confidenceLabelFor(0.01)).toBe(InvestigationConfidenceLabel.Remote);
    expect(confidenceLabelFor(Number.NaN)).toBe(InvestigationConfidenceLabel.Remote);
  });

  it('weights evidence by the reliability of its author and its confidence', () => {
    expect(evidenceReliabilityFactor({ id: 'a', author_reliability: 'A', confidence: 100 })).toBe(1);
    expect(evidenceReliabilityFactor({ id: 'b', author_reliability: 'E', confidence: 0 })).toBe(0.2);
    expect(evidenceReliabilityFactor({ id: 'c' })).toBe(0.525);
    expect(evidenceReliabilityFactor({ id: 'd', author_reliability: 'B - Usually reliable', confidence: 50 })).toBe(0.675);
  });

  it('clamps consistencies to integers in [-2, 2]', () => {
    expect(clampConsistency(3)).toBe(2);
    expect(clampConsistency(-9)).toBe(-2);
    expect(clampConsistency(1.4)).toBe(1);
    expect(clampConsistency('2')).toBe(2);
    expect(clampConsistency('nope')).toBe(0);
  });

  it('orders categories from the most to the least decisive', () => {
    expect(ACH_CATEGORY_WEIGHTS[C.InfrastructureOverlap]).toBeGreaterThan(ACH_CATEGORY_WEIGHTS[C.Tooling]);
    expect(ACH_CATEGORY_WEIGHTS[C.Tooling]).toBeGreaterThan(ACH_CATEGORY_WEIGHTS[C.TtpOverlap]);
    expect(ACH_CATEGORY_WEIGHTS[C.Temporal]).toBeGreaterThan(ACH_CATEGORY_WEIGHTS[C.LanguageTimezone]);
  });
});
