import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';
import { isNotEmptyField, isEmptyField } from '../database/utils';
import { FunctionalError } from '../config/errors';
import type { Vulnerability } from '../generated/graphql';

// --- Types ---

type CvssVersion = 'cvss2' | 'cvss3' | 'cvss4';

export interface CvssFieldUpdate {
  key: string;
  value: (string | number | null)[];
}

export interface CvssConfig {
  allowedMetrics: Record<string, string[]>;
  codeToOpencti: Record<string, string>;
  openctiToCode: Record<string, string>;
  codeToFull: Record<string, Record<string, string>>;
  fullToCode: Record<string, Record<string, string>>;
  ordered: string[];
  prefix?: string;
  baseVectorKey: string;
  baseScoreKey: string;
  temporalScoreKey?: string;
  severityKey: string;
}

// --- Mappings ---

const cvssMappings: Record<CvssVersion, CvssConfig> = {
  cvss2: {
    allowedMetrics: {
      AV: ['L', 'A', 'N'],
      AC: ['H', 'M', 'L'],
      AU: ['M', 'S', 'N'],
      C: ['N', 'P', 'C'],
      I: ['N', 'P', 'C'],
      A: ['N', 'P', 'C'],
      E: ['ND', 'U', 'POC', 'F', 'H'],
      RL: ['ND', 'OF', 'TF', 'W', 'U'],
      RC: ['ND', 'UC', 'UR', 'C'],
    },
    codeToOpencti: {
      AV: 'x_opencti_cvss_v2_access_vector',
      AC: 'x_opencti_cvss_v2_access_complexity',
      AU: 'x_opencti_cvss_v2_authentication',
      C: 'x_opencti_cvss_v2_confidentiality_impact',
      I: 'x_opencti_cvss_v2_integrity_impact',
      A: 'x_opencti_cvss_v2_availability_impact',
      E: 'x_opencti_cvss_v2_exploitability',
      RL: 'x_opencti_cvss_v2_remediation_level',
      RC: 'x_opencti_cvss_v2_report_confidence',
    },
    openctiToCode: {
      x_opencti_cvss_v2_access_vector: 'AV',
      x_opencti_cvss_v2_access_complexity: 'AC',
      x_opencti_cvss_v2_authentication: 'AU',
      x_opencti_cvss_v2_confidentiality_impact: 'C',
      x_opencti_cvss_v2_integrity_impact: 'I',
      x_opencti_cvss_v2_availability_impact: 'A',
      x_opencti_cvss_v2_exploitability: 'E',
      x_opencti_cvss_v2_remediation_level: 'RL',
      x_opencti_cvss_v2_report_confidence: 'RC',
    },
    codeToFull: {
      AV: { N: 'Network', A: 'Adjacent Network', L: 'Local' },
      AC: { H: 'High', M: 'Medium', L: 'Low' },
      AU: { N: 'None', S: 'Single', M: 'Multiple' },
      C: { N: 'None', P: 'Partial', C: 'Complete' },
      I: { N: 'None', P: 'Partial', C: 'Complete' },
      A: { N: 'None', P: 'Partial', C: 'Complete' },
      E: { ND: 'Not Defined', U: 'Unproven', POC: 'Proof-of-Concept', F: 'Functional', H: 'High' },
      RL: { ND: 'Not Defined', OF: 'Official Fix', TF: 'Temporary Fix', W: 'Workaround', U: 'Unavailable' },
      RC: { ND: 'Not Defined', UC: 'Unconfirmed', UR: 'Uncorroborated', C: 'Confirmed' },
    },
    fullToCode: {
      AV: { Network: 'N', 'Adjacent Network': 'A', Local: 'L' },
      AC: { High: 'H', Medium: 'M', Low: 'L' },
      AU: { None: 'N', Single: 'S', Multiple: 'M' },
      C: { None: 'N', Partial: 'P', Complete: 'C' },
      I: { None: 'N', Partial: 'P', Complete: 'C' },
      A: { None: 'N', Partial: 'P', Complete: 'C' },
      E: { 'Not Defined': 'ND', Unproven: 'U', 'Proof-of-Concept': 'POC', Functional: 'F', High: 'H' },
      RL: { 'Not Defined': 'ND', 'Official Fix': 'OF', 'Temporary Fix': 'TF', Workaround: 'W', Unavailable: 'U' },
      RC: { 'Not Defined': 'ND', Unconfirmed: 'UC', Uncorroborated: 'UR', Confirmed: 'C' },
    },
    ordered: ['AV', 'AC', 'AU', 'C', 'I', 'A', 'E', 'RL', 'RC'],
    baseVectorKey: 'x_opencti_cvss_v2_vector',
    baseScoreKey: 'x_opencti_cvss_v2_base_score',
    temporalScoreKey: 'x_opencti_cvss_v2_temporal_score',
    severityKey: '',
  },
  cvss3: {
    allowedMetrics: {
      AV: ['N', 'A', 'L', 'P'],
      AC: ['L', 'H'],
      PR: ['N', 'L', 'H'],
      UI: ['N', 'R'],
      S: ['U', 'C'],
      C: ['H', 'L', 'N'],
      I: ['H', 'L', 'N'],
      A: ['H', 'L', 'N'],
      E: ['X', 'U', 'P', 'F', 'H'],
      RL: ['X', 'O', 'T', 'W', 'U'],
      RC: ['X', 'U', 'R', 'C'],
    },
    codeToOpencti: {
      AV: 'x_opencti_cvss_attack_vector',
      AC: 'x_opencti_cvss_attack_complexity',
      PR: 'x_opencti_cvss_privileges_required',
      UI: 'x_opencti_cvss_user_interaction',
      S: 'x_opencti_cvss_scope',
      C: 'x_opencti_cvss_confidentiality_impact',
      I: 'x_opencti_cvss_integrity_impact',
      A: 'x_opencti_cvss_availability_impact',
      E: 'x_opencti_cvss_exploit_code_maturity',
      RL: 'x_opencti_cvss_remediation_level',
      RC: 'x_opencti_cvss_report_confidence',
    },
    openctiToCode: {
      x_opencti_cvss_attack_vector: 'AV',
      x_opencti_cvss_attack_complexity: 'AC',
      x_opencti_cvss_privileges_required: 'PR',
      x_opencti_cvss_user_interaction: 'UI',
      x_opencti_cvss_scope: 'S',
      x_opencti_cvss_confidentiality_impact: 'C',
      x_opencti_cvss_integrity_impact: 'I',
      x_opencti_cvss_availability_impact: 'A',
      x_opencti_cvss_exploit_code_maturity: 'E',
      x_opencti_cvss_remediation_level: 'RL',
      x_opencti_cvss_report_confidence: 'RC',
    },
    codeToFull: {
      AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
      AC: { L: 'Low', H: 'High' },
      PR: { N: 'None', L: 'Low', H: 'High' },
      UI: { N: 'None', R: 'Required' },
      S: { U: 'Unchanged', C: 'Changed' },
      C: { N: 'None', L: 'Low', H: 'High' },
      I: { N: 'None', L: 'Low', H: 'High' },
      A: { N: 'None', L: 'Low', H: 'High' },
      E: { X: 'Not Defined', U: 'Unproven', P: 'Proof-of-Concept', F: 'Functional', H: 'High' },
      RL: { X: 'Not Defined', O: 'Official Fix', T: 'Temporary Fix', W: 'Workaround', U: 'Unavailable' },
      RC: { X: 'Not Defined', U: 'Unconfirmed', R: 'Reasonable', C: 'Confirmed' },
    },
    fullToCode: {
      AV: { Network: 'N', Adjacent: 'A', Local: 'L', Physical: 'P' },
      AC: { Low: 'L', High: 'H' },
      PR: { None: 'N', Low: 'L', High: 'H' },
      UI: { None: 'N', Required: 'R' },
      S: { Unchanged: 'U', Changed: 'C' },
      C: { None: 'N', Low: 'L', High: 'H' },
      I: { None: 'N', Low: 'L', High: 'H' },
      A: { None: 'N', Low: 'L', High: 'H' },
      E: { 'Not Defined': 'X', Unproven: 'U', 'Proof-of-Concept': 'P', Functional: 'F', High: 'H' },
      RL: { 'Not Defined': 'X', 'Official Fix': 'O', 'Temporary Fix': 'T', Workaround: 'W', Unavailable: 'U' },
      RC: { 'Not Defined': 'X', Unconfirmed: 'U', Reasonable: 'R', Confirmed: 'C' },
    },
    ordered: ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC'],
    prefix: 'CVSS:3.1/',
    baseVectorKey: 'x_opencti_cvss_vector',
    baseScoreKey: 'x_opencti_cvss_base_score',
    temporalScoreKey: 'x_opencti_cvss_temporal_score',
    severityKey: 'x_opencti_cvss_base_severity',
  },
  cvss4: {
    allowedMetrics: {
      AV: ['N', 'A', 'L', 'P'],
      AC: ['L', 'H'],
      AT: ['N', 'P'],
      PR: ['N', 'L', 'H'],
      UI: ['N', 'P', 'A'],
      VC: ['H', 'L', 'N'],
      VI: ['H', 'L', 'N'],
      VA: ['H', 'L', 'N'],
      SC: ['H', 'L', 'N'],
      SI: ['H', 'L', 'N'],
      SA: ['H', 'L', 'N'],
      E: ['X', 'A', 'P', 'U'],
    },
    codeToOpencti: {
      AV: 'x_opencti_cvss_v4_attack_vector',
      AC: 'x_opencti_cvss_v4_attack_complexity',
      AT: 'x_opencti_cvss_v4_attack_requirements',
      PR: 'x_opencti_cvss_v4_privileges_required',
      UI: 'x_opencti_cvss_v4_user_interaction',
      VC: 'x_opencti_cvss_v4_confidentiality_impact_v',
      SC: 'x_opencti_cvss_v4_confidentiality_impact_s',
      VI: 'x_opencti_cvss_v4_integrity_impact_v',
      SI: 'x_opencti_cvss_v4_integrity_impact_s',
      VA: 'x_opencti_cvss_v4_availability_impact_v',
      SA: 'x_opencti_cvss_v4_availability_impact_s',
      E: 'x_opencti_cvss_v4_exploit_maturity',
    },
    openctiToCode: {
      x_opencti_cvss_v4_attack_vector: 'AV',
      x_opencti_cvss_v4_attack_complexity: 'AC',
      x_opencti_cvss_v4_attack_requirements: 'AT',
      x_opencti_cvss_v4_privileges_required: 'PR',
      x_opencti_cvss_v4_user_interaction: 'UI',
      x_opencti_cvss_v4_confidentiality_impact_v: 'VC',
      x_opencti_cvss_v4_integrity_impact_v: 'VI',
      x_opencti_cvss_v4_availability_impact_v: 'VA',
      x_opencti_cvss_v4_confidentiality_impact_s: 'SC',
      x_opencti_cvss_v4_integrity_impact_s: 'SI',
      x_opencti_cvss_v4_availability_impact_s: 'SA',
      x_opencti_cvss_v4_exploit_maturity: 'E',
    },
    codeToFull: {
      AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
      AC: { L: 'Low', H: 'High' },
      AT: { N: 'None', P: 'Present' },
      PR: { N: 'None', L: 'Low', H: 'High' },
      UI: { N: 'None', P: 'Passive', A: 'Active' },
      VC: { H: 'High', L: 'Low', N: 'None' },
      VI: { H: 'High', L: 'Low', N: 'None' },
      VA: { H: 'High', L: 'Low', N: 'None' },
      SC: { H: 'High', L: 'Low', N: 'None' },
      SI: { H: 'High', L: 'Low', N: 'None' },
      SA: { H: 'High', L: 'Low', N: 'None' },
      E: { X: 'Not Defined', A: 'Unreliable', P: 'Proof-of-Concept', U: 'Unproven' }
    },
    fullToCode: {
      AV: { Network: 'N', Adjacent: 'A', Local: 'L', Physical: 'P' },
      AC: { Low: 'L', High: 'H' },
      AT: { None: 'N', Present: 'P' },
      PR: { None: 'N', Low: 'L', High: 'H' },
      UI: { None: 'N', Passive: 'P', Active: 'A' },
      VC: { High: 'H', Low: 'L', None: 'N' },
      VI: { High: 'H', Low: 'L', None: 'N' },
      VA: { High: 'H', Low: 'L', None: 'N' },
      SC: { High: 'H', Low: 'L', None: 'N' },
      SI: { High: 'H', Low: 'L', None: 'N' },
      SA: { High: 'H', Low: 'L', None: 'N' },
      E: { 'Not Defined': 'X', Unreliable: 'A', 'Proof-of-Concept': 'P', Unproven: 'U' }
    },
    ordered: [
      'AV', 'AC', 'AT', 'PR', 'UI',
      'VC', 'VI', 'VA',
      'SC', 'SI', 'SA',
      'E'
    ],
    prefix: 'CVSS:4.0/',
    baseVectorKey: 'x_opencti_cvss_v4_vector',
    baseScoreKey: 'x_opencti_cvss_v4_base_score',
    severityKey: 'x_opencti_cvss_v4_base_severity',
  },
};

const cvss2OutputKeyCase: Record<string, string> = {
  AV: 'AV',
  AC: 'AC',
  AU: 'Au',
  C: 'C',
  I: 'I',
  A: 'A',
  E: 'E',
  RL: 'RL',
  RC: 'RC',
};

// --- Helpers ---

const getFullValue = (
  metric: string | undefined,
  value: string | null,
  config: CvssConfig
): string | null => {
  if (!metric || value === null) return value;
  const map = config.codeToFull[metric];
  if (!map) return value;

  // Try code lookup (input might be a code, e.g., "N")
  if (map[value]) return map[value];

  // Try full label lookup, case-insensitive
  const found = Object.values(map).find(
    (full) => full.toLowerCase() === value.toLowerCase()
  );
  if (found) return found;

  // If still not found, maybe user entered the code in lowercase ("n" instead of "N")
  const codeFromLower = Object.keys(map).find(
    (code) => code.toLowerCase() === value.toLowerCase()
  );
  if (codeFromLower) return map[codeFromLower];

  return value;
};

const getCodeValue = (
  metric: string,
  value: string,
  config: CvssConfig
): string => {
  const map = config.fullToCode[metric];
  if (!map) return value;

  // Direct match (case-sensitive)
  if (map[value]) return map[value];

  // Case-insensitive full label match
  const found = Object.entries(map).find(
    ([full]) => full.toLowerCase() === value.toLowerCase()
  );
  if (found) return found[1];

  // Also, code input in lowercase? ("n" instead of "N")
  const codeFromLower = Object.entries(map).find(
    ([, code]) => code.toLowerCase() === value.toLowerCase()
  );
  if (codeFromLower) return codeFromLower[1];

  return value;
};

// --- CVSS Criticity ---

export const getCvssCriticity = (score: number | null | undefined): string | null => {
  if (typeof score !== 'number' || score < 0 || score > 10) return null;
  if (score === 0.0) return 'Unknown';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
};

// --- API (fully typed) ---

export const isValidCvssVector = (
  version: CvssVersion,
  vector: string | null | undefined
): boolean => {
  const config = cvssMappings[version];
  if (isEmptyField(vector)) return true;
  if (typeof vector !== 'string') return false;
  if (version === 'cvss3' && !vector.startsWith('CVSS:3.')) return false;
  if (version === 'cvss4' && !vector.startsWith('CVSS:4.0/')) return false;
  if (version === 'cvss2' && !vector.toUpperCase().includes('AV:')) return false;
  const seen = new Set<string>();
  const body = config.prefix ? vector.replace(config.prefix, '') : vector;
  return body.split('/').every((entry) => {
    const [rawKey, rawValue] = entry.split(':');
    const key = rawKey && rawKey.toUpperCase();
    const value = rawValue && rawValue.toUpperCase();
    if (!key || !value) return false;
    if (!config.allowedMetrics[key]) return false;
    if (!config.allowedMetrics[key].includes(value)) return false;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

export const parseCvssVector = (
  version: CvssVersion,
  vector: string | null | undefined,
  initialScore: number | null | undefined = null,
  asObject = false
): CvssFieldUpdate[] | Record<string, unknown> => {
  const config = cvssMappings[version];
  const { codeToOpencti } = config;
  if (isEmptyField(vector)) {
    const nullFields: CvssFieldUpdate[] = Object.values(codeToOpencti).map((key) => ({ key, value: [null] }));
    let result: CvssFieldUpdate[] = [];
    if (version === 'cvss2') {
      result = [
        { key: config.baseVectorKey, value: [null] },
        ...nullFields,
        { key: config.baseScoreKey, value: [null] },
        { key: config.temporalScoreKey!, value: [null] }
      ];
    } else {
      result = [
        ...nullFields,
        { key: config.baseScoreKey, value: [null] }
      ];
      if (config.severityKey) result.push({ key: config.severityKey, value: [null] });
      if (config.temporalScoreKey) result.push({ key: config.temporalScoreKey, value: [null] });
    }
    return asObject ? Object.fromEntries(result.map((e) => [e.key, e.value[0]])) : result;
  }
  const seen = new Set<string>();
  const parts = (config.prefix ? vector!.replace(config.prefix, '') : vector!).split('/');
  const parsedVector: CvssFieldUpdate[] = parts
    .map((part): CvssFieldUpdate | null => {
      const [rawKey, rawValue] = part.split(':');
      const key = rawKey?.toUpperCase();
      let value: string | null = rawValue !== undefined ? rawValue : null;
      value = getFullValue(key, value, config) ?? null;
      if (key && codeToOpencti[key] && !seen.has(key)) {
        seen.add(key);
        return { key: codeToOpencti[key], value: [value as string | number | null] };
      }
      return null;
    })
    .filter((e): e is CvssFieldUpdate => e !== null);
  const existingKeys = parsedVector.map((e) => e.key);
  const missingKeys = Object.values(codeToOpencti).filter((k) => !existingKeys.includes(k));
  const nulls: CvssFieldUpdate[] = missingKeys.map((key) => ({ key, value: [null] }));
  let scores: any = null;
  if (version === 'cvss3') {
    scores = new Cvss3P1(vector!).calculateScores();
  } else if (version === 'cvss2') {
    scores = new Cvss2(vector!).calculateScores();
  } else if (version === 'cvss4') {
    scores = new Cvss4P0(vector!).calculateScores();
  }
  let result: CvssFieldUpdate[] = [];
  if (version === 'cvss2') {
    if (isEmptyField(initialScore)) {
      result = [
        ...parsedVector,
        ...nulls,
        { key: config.baseVectorKey, value: [vector] },
        { key: config.baseScoreKey, value: [scores.base] },
        { key: config.temporalScoreKey!, value: [isNotEmptyField(scores.temporal) ? scores.temporal : null] }
      ];
    } else {
      result = [
        ...parsedVector,
        ...nulls,
        { key: config.baseVectorKey, value: [vector ?? null] }
      ];
    }
  } else if (isEmptyField(initialScore)) {
    result = [
      ...parsedVector,
      ...nulls,
      { key: config.baseScoreKey, value: [scores.overall] }
    ];
    if (config.severityKey) result.push({ key: config.severityKey, value: [getCvssCriticity(scores.overall)] });
    if (config.temporalScoreKey && isNotEmptyField(scores.temporal)) result.push({ key: config.temporalScoreKey, value: [scores.temporal] });
  } else {
    result = [
      ...parsedVector,
      ...nulls
    ];
    if (config.severityKey) result.push({ key: config.severityKey, value: [getCvssCriticity(initialScore ?? 0)] });
  }
  return asObject ? Object.fromEntries(result.map((e) => [e.key, e.value[0]])) : result;
};

export const updateCvssVector = (
  version: CvssVersion,
  existingVector: string | null | undefined,
  updates: CvssFieldUpdate[],
  initialScore: number | null | undefined,
  asObject = false
): CvssFieldUpdate[] | Record<string, unknown> => {
  if (updates.length === 0) {
    return {};
  }
  const config = cvssMappings[version];
  const { openctiToCode, ordered, prefix, baseVectorKey, baseScoreKey, temporalScoreKey, severityKey } = config;
  const initialParts: [string, string | undefined][] = (existingVector || '')
    .replace(prefix || '', '')
    .split('/')
    .filter((s) => s.includes(':'))
    .map((part) => {
      const [k, v] = part.split(':');
      return [k && k.toUpperCase(), v];
    });
  const parts = new Map<string, string | undefined>(initialParts);
  updates.forEach(({ key, value }) => {
    const metric = openctiToCode[key];
    if (metric) {
      const val = Array.isArray(value) ? value[0] : value;
      if (val !== null && val !== undefined) {
        parts.set(metric, getCodeValue(metric, String(val), config));
      }
    }
  });
  const updatedVector = (prefix || '')
      + ordered
        .filter((k) => parts.has(k))
        .map((k) => (version === 'cvss2'
          ? `${cvss2OutputKeyCase[k] || k}:${parts.get(k)}`
          : `${k}:${parts.get(k)}`))
        .join('/');
  let scores: any = null;
  if (version === 'cvss3') {
    scores = new Cvss3P1(updatedVector).calculateScores();
  } else if (version === 'cvss2') {
    scores = new Cvss2(updatedVector).calculateScores();
  } else if (version === 'cvss4') {
    scores = new Cvss4P0(updatedVector).calculateScores();
  }
  let result: CvssFieldUpdate[] = [];
  if (version === 'cvss2') {
    if (isEmptyField(initialScore)) {
      result = [
        { key: baseVectorKey, value: [updatedVector] },
        { key: baseScoreKey, value: [scores.base] },
        { key: temporalScoreKey!, value: [isNotEmptyField(scores.temporal) ? scores.temporal : null] }
      ];
    } else {
      result = [{ key: baseVectorKey, value: [updatedVector] }];
    }
  } else if (isEmptyField(initialScore)) {
    result = [
      { key: baseVectorKey, value: [updatedVector] },
      { key: baseScoreKey, value: [scores.overall] }
    ];
    if (severityKey) result.push({ key: severityKey, value: [getCvssCriticity(scores.overall)] });
    if (temporalScoreKey && isNotEmptyField(scores.temporal)) result.push({ key: temporalScoreKey, value: [scores.temporal] });
  } else {
    result = [{ key: baseVectorKey, value: [updatedVector] }];
    if (severityKey) result.push({ key: severityKey, value: [getCvssCriticity(initialScore ?? 0)] });
  }
  return asObject ? Object.fromEntries(result.map((e) => [e.key, e.value[0]])) : result;
};

export const generateVulnerabilitiesUpdates = (initial: Vulnerability, updates: CvssFieldUpdate[]) => {
  const newUpdates = [];
  if (updates.some((e) => e.key === 'x_opencti_cvss_v2_vector')) {
    const vectorUpdate = updates.filter((e) => e.key === 'x_opencti_cvss_v2_vector').at(0);
    const vector = vectorUpdate?.value?.at(0) as string;
    if (!isValidCvssVector('cvss2', vector)) {
      throw FunctionalError('This is not a valid CVSS2 vector');
    }
    newUpdates.push(...parseCvssVector('cvss2', vector) as CvssFieldUpdate[]);
  } else if (updates.some((e) => e.key.startsWith('x_opencti_cvss_v2_'))) {
    const updatedVectorParts = updates.filter((e) => e.key.startsWith('x_opencti_cvss_v2_') && !e.key.includes('base') && !e.key.includes('temporal'));
    if (updatedVectorParts.length > 0) {
      newUpdates.push(...updateCvssVector('cvss2', initial.x_opencti_cvss_v2_vector, updatedVectorParts, initial.x_opencti_cvss_v2_base_score) as CvssFieldUpdate[]);
    }
  }
  if (updates.some((e) => e.key === 'x_opencti_cvss_vector')) {
    const vectorUpdate = updates.filter((e) => e.key === 'x_opencti_cvss_vector').at(0);
    const vector = vectorUpdate?.value?.at(0) as string;
    if (!isValidCvssVector('cvss3', vector)) {
      throw FunctionalError('This is not a valid CVSS3 vector');
    }
    newUpdates.push(...parseCvssVector('cvss3', vector) as CvssFieldUpdate[]);
  } else if (updates.some((e) => e.key.startsWith('x_opencti_cvss_'))) {
    let baseScore = initial.x_opencti_cvss_base_score;
    if (updates.some((e) => e.key === 'x_opencti_cvss_base_score')) {
      baseScore = updates.filter((e) => e.key === 'x_opencti_cvss_base_score').at(0)?.value.at(0) as number;
      newUpdates.push({ key: 'x_opencti_cvss_base_severity', values: [getCvssCriticity(baseScore)] });
    }
    const updatedVectorParts = updates.filter((e) => e.key.startsWith('x_opencti_cvss_') && !e.key.includes('base') && !e.key.includes('temporal') && !e.key.startsWith('x_opencti_cvss_v'));
    if (updatedVectorParts.length > 0) {
      newUpdates.push(...updateCvssVector('cvss3', initial.x_opencti_cvss_vector, updatedVectorParts, baseScore) as CvssFieldUpdate[]);
    }
  }
  if (updates.some((e) => e.key === 'x_opencti_cvss_v4_vector')) {
    const vectorUpdate = updates.filter((e) => e.key === 'x_opencti_cvss_v4_vector').at(0);
    const vector = vectorUpdate?.value?.at(0) as string;
    if (!isValidCvssVector('cvss4', vector)) {
      throw FunctionalError('This is not a valid CVSS4 vector');
    }
    newUpdates.push(...parseCvssVector('cvss4', vector) as CvssFieldUpdate[]);
  } else if (updates.some((e) => e.key.startsWith('x_opencti_cvss_v4_'))) {
    let baseScore = initial.x_opencti_cvss_v4_base_score;
    if (updates.some((e) => e.key === 'x_opencti_cvss_v4_base_score')) {
      baseScore = updates.filter((e) => e.key === 'x_opencti_cvss_v4_base_score').at(0)?.value.at(0) as number;
      newUpdates.push({ key: 'x_opencti_cvss_v4_base_severity', values: [getCvssCriticity(baseScore)] });
    }
    const updatedVectorParts = updates.filter((e) => e.key.startsWith('x_opencti_cvss_v4_') && !e.key.includes('base'));
    if (updatedVectorParts.length > 0) {
      newUpdates.push(...updateCvssVector('cvss4', initial.x_opencti_cvss_v4_vector, updatedVectorParts, baseScore) as CvssFieldUpdate[]);
    }
  }
  return newUpdates;
};
