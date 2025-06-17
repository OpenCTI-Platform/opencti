import { Cvss2, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';
import { isNotEmptyField, isEmptyField } from '../database/utils';

export interface CvssFieldUpdate {
  key: string;
  value: unknown[];
}

// --- Shared logic ---

const getCvssCriticity = (score: number | null): string | null => {
  if (typeof score !== 'number' || score < 0 || score > 10) return null;
  if (score === 0.0) return 'Unknown';
  if (score <= 3.9) return 'LOW';
  if (score <= 6.9) return 'MEDIUM';
  if (score <= 8.9) return 'HIGH';
  return 'CRITICAL';
};

// --- CVSS 4 ---

export const isValidCvss4Vector = (vector: string | null | undefined): boolean => {
  if (isEmptyField(vector)) return true;
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:4.0/')) return false;
  const allowedMetrics: Record<string, string[]> = {
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
    MAV: ['N', 'A', 'L', 'P', 'X'],
    MAC: ['L', 'H', 'X'],
    MAT: ['N', 'P', 'X'],
    MPR: ['N', 'L', 'H', 'X'],
    MUI: ['N', 'P', 'A', 'X'],
    MVC: ['H', 'L', 'N', 'X'],
    MVI: ['H', 'L', 'N', 'X'],
    MVA: ['H', 'L', 'N', 'X'],
    MSC: ['H', 'L', 'N', 'X'],
    MSI: ['H', 'L', 'N', 'X'],
    MSA: ['H', 'L', 'N', 'X'],
    E: ['X', 'A', 'P', 'U']
  };
  const seen = new Set<string>();
  return vector
    .slice('CVSS:4.0/'.length)
    .split('/')
    .every((pair) => {
      const [key, value] = pair.split(':');
      return (
        key && value && allowedMetrics[key] && allowedMetrics[key].includes(value) && !seen.has(key) && seen.add(key)
      );
    });
};

export const parseCvss4Vector = (vector: string | null | undefined, initialScore: number | null | undefined, asObject = false): CvssFieldUpdate[] | Record<string, unknown> => {
  const mapping: Record<string, string> = {
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
  };
  if (isEmptyField(vector)) {
    return [
      ...Object.values(mapping).map((key) => ({ key, value: [null] })),
      { key: 'x_opencti_cvss_v4_base_score', value: [null] },
      { key: 'x_opencti_cvss_v4_base_severity', value: [null] },
    ];
  }
  const seen = new Set<string>();
  const parsedVector = vector!
    .slice('CVSS:4.0/'.length)
    .split('/')
    .map((part) => {
      const [key, value] = part.split(':');
      return mapping[key] && !seen.has(key)
        ? (seen.add(key), { key: mapping[key], value: [value] })
        : null;
    })
    .filter((e) => e !== null) as CvssFieldUpdate[];
  const missing = Object.values(mapping).filter((k) => !parsedVector.map((e) => e.key).includes(k));
  const nulls = missing.map((key) => ({ key, value: [null] }));
  const calculator = new Cvss4P0(vector!);
  const scores = calculator.calculateScores();
  const result = isEmptyField(initialScore) ? [
    ...parsedVector,
    ...nulls,
    { key: 'x_opencti_cvss_v4_base_score', value: [scores.overall] },
    { key: 'x_opencti_cvss_v4_base_severity', value: [getCvssCriticity(scores.overall)] },
  ] : [...parsedVector, ...nulls, { key: 'x_opencti_cvss_v4_base_severity', value: [getCvssCriticity(initialScore ?? 0)] }];
  if (asObject) {
    return Object.fromEntries(result.map(({ key, value }) => [key, value]));
  }
  return result;
};

// Define allowed metric keys
type Cvss4Metric =
    | 'AV' | 'AC' | 'AT' | 'PR' | 'UI'
    | 'VC' | 'VI' | 'VA'
    | 'SC' | 'SI' | 'SA'
    | 'E';

type Cvss4ValueMap = {
  [metric in Cvss4Metric]: Record<string, string>
};

const CVSS4_VALUE_MAP: Cvss4ValueMap = {
  AV: { N: 'NETWORK', A: 'ADJACENT', L: 'LOCAL', P: 'PHYSICAL' },
  AC: { L: 'LOW', H: 'HIGH' },
  AT: { N: 'NONE', P: 'PRESENT' },
  PR: { N: 'NONE', L: 'LOW', H: 'HIGH' },
  UI: { N: 'NONE', R: 'REQUIRED' },
  VC: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  VI: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  VA: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  SC: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  SI: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  SA: { H: 'HIGH', L: 'LOW', N: 'NONE' },
  E: { X: 'NOT_DEFINED', A: 'UNRELIABLE', P: 'PROOF_OF_CONCEPT', F: 'FUNCTIONAL', H: 'HIGH' }
};

export const cvss4NormalizeValue = (metric: Cvss4Metric, val: unknown): string => {
  if (!val) return '';
  const valueUpper = String(val).trim().toUpperCase();
  // Direct letter match
  if (CVSS4_VALUE_MAP[metric] && valueUpper in CVSS4_VALUE_MAP[metric]) {
    return valueUpper;
  }
  // String (true value) match
  if (CVSS4_VALUE_MAP[metric]) {
    const found = Object.entries(CVSS4_VALUE_MAP[metric])
      .find(([, full]) => full === valueUpper || full === String(val).trim());
    if (found) return found[0];
  }
  return valueUpper;
};

export const updateCvss4Vector = (
  existingVector: string | null | undefined,
  updates: CvssFieldUpdate[],
  initialScore: number | null | undefined,
  asObject = false,
): CvssFieldUpdate[] | Record<string, unknown> => {
  const keyMap: Record<string, Cvss4Metric> = {
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
  };
  const initialParts = (existingVector || '')
    .replace(/^CVSS:4\.0\//, '')
    .split('/')
    .filter((s) => s.includes(':'))
    .map((part) => {
      const [k, v] = part.split(':');
      return [k.toUpperCase(), v];
    });
  const parts = new Map<string, string>(initialParts as [string, string][]);
  updates.forEach(({ key, value }) => {
    const metric = keyMap[key];
    if (metric) {
      const val = Array.isArray(value) ? value[0] : value;
      if (val !== null && val !== undefined) {
        parts.set(metric, cvss4NormalizeValue(metric, String(val)));
      }
    }
  });
  const ordered = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'E'];
  const updatedVector = `CVSS:4.0/${ordered.filter((k) => parts.has(k)).map((k) => `${k}:${parts.get(k)}`).join('/')}`;
  const calculator = new Cvss4P0(updatedVector);
  const scores = calculator.calculateScores();
  const result = isEmptyField(initialScore) ? [
    { key: 'x_opencti_cvss_v4_vector', value: [updatedVector] },
    { key: 'x_opencti_cvss_v4_base_score', value: [scores.overall] },
    { key: 'x_opencti_cvss_v4_base_severity', value: [getCvssCriticity(scores.overall)] }
  ] : [
    { key: 'x_opencti_cvss_v4_vector', value: [updatedVector] },
    { key: 'x_opencti_cvss_v4_base_severity', value: [getCvssCriticity(initialScore ?? 0)] }
  ];
  if (asObject) {
    return Object.fromEntries(result.map(({ key, value }) => [key, value[0]]));
  }
  return result;
};

// --- CVSS 3 ---

export const isValidCvss3Vector = (vector: string | null | undefined): boolean => {
  if (isEmptyField(vector)) return true;
  if (typeof vector !== 'string' || !vector.startsWith('CVSS:3.')) return false;
  const allowedMetrics: Record<string, string[]> = {
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
  };
  const seen = new Set<string>();
  return vector
    .slice(vector.indexOf('/') + 1)
    .split('/')
    .every((entry) => {
      const [key, value] = entry.split(':');
      return (
        key && value && allowedMetrics[key] && allowedMetrics[key].includes(value) && !seen.has(key) && seen.add(key)
      );
    });
};

export const parseCvss3Vector = (vector: string | null | undefined, initialScore: number | null | undefined, asObject = false): CvssFieldUpdate[] | Record<string, unknown> => {
  const mapping: Record<string, string> = {
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
  };
  if (isEmptyField(vector)) {
    return [
      ...Object.values(mapping).map((key) => ({ key, value: [null] })),
      { key: 'x_opencti_cvss_base_score', value: [null] },
      { key: 'x_opencti_cvss_base_severity', value: [null] },
      { key: 'x_opencti_cvss_temporal_score', value: [null] }
    ];
  }
  const seen = new Set<string>();
  const parsedVector = vector!
    .slice(vector!.indexOf('/') + 1)
    .split('/')
    .map((part) => {
      const [key, value] = part.split(':');
      return mapping[key] && !seen.has(key)
        ? (seen.add(key), { key: mapping[key], value: [value] })
        : null;
    })
    .filter((e) => e !== null) as CvssFieldUpdate[];
  const existingKeys = parsedVector.map((e) => e.key);
  const missingKeys = Object.values(mapping).filter((k) => !existingKeys.includes(k));
  const nulls = missingKeys.map((key) => ({ key, value: [null] }));
  const cvss3 = new Cvss3P1(vector!);
  const scores = cvss3.calculateScores();
  const result = isEmptyField(initialScore) ? [
    ...parsedVector,
    ...nulls,
    { key: 'x_opencti_cvss_base_score', value: [scores.overall] },
    { key: 'x_opencti_cvss_base_severity', value: [getCvssCriticity(scores.overall)] },
    { key: 'x_opencti_cvss_temporal_score', value: [isNotEmptyField(scores.temporal) ? scores.temporal : null] }
  ] : [...parsedVector, ...nulls, { key: 'x_opencti_cvss_base_severity', value: [getCvssCriticity(initialScore ?? 0)] }];
  if (asObject) {
    return Object.fromEntries(result.map((e) => [e.key, e.value[0]]));
  }
  return result;
};

export const updateCvss3VectorWithScores = (
  existingVector: string | null | undefined,
  updates: CvssFieldUpdate[],
  initialScore: number | null | undefined,
  asObject = false,
): CvssFieldUpdate[] | Record<string, unknown> => {
  const keyMap: Record<string, string> = {
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
  };
  const initialParts = (existingVector || '')
    .replace(/^CVSS:3\.\d+\//, '')
    .split('/')
    .filter((s) => s.includes(':'))
    .map((part) => {
      const [k, v] = part.split(':');
      return [k.toUpperCase(), v];
    });
  const parts = new Map<string, string>(initialParts as [string, string][]);
  updates.forEach(({ key, value }) => {
    const metric = keyMap[key];
    if (metric) {
      const val = Array.isArray(value) ? value[0] : value;
      if (val !== null && val !== undefined) {
        parts.set(metric, String(val));
      }
    }
  });
  const ordered = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A', 'E', 'RL', 'RC'];
  const updatedVector = `CVSS:3.1/${ordered.filter((k) => parts.has(k)).map((k) => `${k}:${parts.get(k)}`).join('/')}`;
  const calculator = new Cvss3P1(updatedVector);
  const scores = calculator.calculateScores();
  const result = isEmptyField(initialScore) ? [
    { key: 'x_opencti_cvss_vector', value: [updatedVector] },
    { key: 'x_opencti_cvss_base_score', value: [scores.overall] },
    { key: 'x_opencti_cvss_base_severity', value: [getCvssCriticity(scores.overall)] },
    { key: 'x_opencti_cvss_temporal_score', value: [isNotEmptyField(scores.temporal) ? scores.temporal : null] }
  ] : [{ key: 'x_opencti_cvss_vector', value: [updatedVector] }, { key: 'x_opencti_cvss_base_severity', value: [getCvssCriticity(initialScore ?? 0)] }];
  if (asObject) {
    return Object.fromEntries(result.map((e) => [e.key, e.value[0]]));
  }
  return result;
};

// --- CVSS 2 ---

export const isValidCvss2Vector = (vector: string | null | undefined): boolean => {
  if (isEmptyField(vector)) return true;
  if (typeof vector !== 'string' || !vector.toUpperCase().includes('AV:')) return false;
  const allowedMetrics: Record<string, string[]> = {
    AV: ['L', 'A', 'N'],
    AC: ['H', 'M', 'L'],
    AU: ['M', 'S', 'N'],
    C: ['N', 'P', 'C'],
    I: ['N', 'P', 'C'],
    A: ['N', 'P', 'C'],
    E: ['ND', 'U', 'POC', 'F', 'H'],
    RL: ['ND', 'OF', 'TF', 'W', 'U'],
    RC: ['ND', 'UC', 'UR', 'C'],
  };
  const seen = new Set<string>();
  return vector
    .split('/')
    .every((entry) => {
      const [rawKey, rawValue] = entry.split(':');
      const key = rawKey?.toUpperCase();
      const value = rawValue?.toUpperCase();
      return (
        key && value && allowedMetrics[key] && allowedMetrics[key].includes(value) && !seen.has(key) && seen.add(key)
      );
    });
};

export const parseCvss2Vector = (vector: string | null | undefined, initialScore: number | null | undefined, asObject = false): CvssFieldUpdate[] | Record<string, unknown> => {
  const mapping: Record<string, string> = {
    AV: 'x_opencti_cvss_v2_access_vector',
    AC: 'x_opencti_cvss_v2_access_complexity',
    AU: 'x_opencti_cvss_v2_authentication',
    C: 'x_opencti_cvss_v2_confidentiality_impact',
    I: 'x_opencti_cvss_v2_integrity_impact',
    A: 'x_opencti_cvss_v2_availability_impact',
    E: 'x_opencti_cvss_v2_exploitability',
    RL: 'x_opencti_cvss_v2_remediation_level',
    RC: 'x_opencti_cvss_v2_report_confidence',
  };
  if (isEmptyField(vector)) {
    return [
      { key: 'x_opencti_cvss_v2_vector', value: [null] },
      ...Object.values(mapping).map((key) => ({ key, value: [null] })),
      { key: 'x_opencti_cvss_v2_base_score', value: [null] },
      { key: 'x_opencti_cvss_v2_temporal_score', value: [null] },
    ];
  }
  const seen = new Set<string>();
  const parsedVector = vector!
    .split('/')
    .map((part) => {
      const [rawKey, rawValue] = part.split(':');
      const key = rawKey?.toUpperCase();
      const value = rawValue?.toUpperCase();
      return mapping[key] && !seen.has(key)
        ? (seen.add(key), { key: mapping[key], value: [value] })
        : null;
    })
    .filter((e) => e !== null) as CvssFieldUpdate[];
  const existingKeys = parsedVector.map((e) => e.key);
  const missingKeys = Object.values(mapping).filter((k) => !existingKeys.includes(k));
  const nulls = missingKeys.map((key) => ({ key, value: [null] }));
  const cvss2 = new Cvss2(vector!);
  const scores = cvss2.calculateScores();
  const result = isEmptyField(initialScore) ? [
    ...parsedVector,
    ...nulls,
    { key: 'x_opencti_cvss_v2_vector', value: [vector] },
    { key: 'x_opencti_cvss_v2_base_score', value: [scores.base] },
    { key: 'x_opencti_cvss_v2_temporal_score', value: [isNotEmptyField(scores.temporal) ? scores.temporal : null] }
  ] : [
    ...parsedVector,
    ...nulls,
    { key: 'x_opencti_cvss_v2_vector', value: [vector] },
  ];
  if (asObject) {
    return Object.fromEntries(result.map((e) => [e.key, e.value[0]]));
  }
  return result;
};

export const updateCvss2Vector = (
  existingVector: string | null | undefined,
  updates: CvssFieldUpdate[],
  initialScore: number | null | undefined,
  asObject = false,
): CvssFieldUpdate[] | Record<string, unknown> => {
  const keyMap: Record<string, string> = {
    x_opencti_cvss_v2_access_vector: 'AV',
    x_opencti_cvss_v2_access_complexity: 'AC',
    x_opencti_cvss_v2_authentication: 'AU',
    x_opencti_cvss_v2_confidentiality_impact: 'C',
    x_opencti_cvss_v2_integrity_impact: 'I',
    x_opencti_cvss_v2_availability_impact: 'A',
    x_opencti_cvss_v2_exploitability: 'E',
    x_opencti_cvss_v2_remediation_level: 'RL',
    x_opencti_cvss_v2_report_confidence: 'RC',
  };
  const initialParts = (existingVector || '')
    .split('/')
    .filter((s) => s.includes(':'))
    .map((part) => {
      const [k, v] = part.split(':');
      return [k.toUpperCase(), v];
    });
  const parts = new Map<string, string>(initialParts as [string, string][]);
  updates.forEach(({ key, value }) => {
    const metric = keyMap[key];
    if (metric) {
      const val = Array.isArray(value) ? value[0] : value;
      if (val !== null && val !== undefined) {
        parts.set(metric, String(val));
      }
    }
  });
  const ordered = ['AV', 'AC', 'AU', 'C', 'I', 'A', 'E', 'RL', 'RC'];
  const updatedVector = ordered.filter((k) => parts.has(k)).map((k) => `${k}:${parts.get(k)}`).join('/');
  const calculator = new Cvss2(updatedVector);
  const scores = calculator.calculateScores();
  const result = isEmptyField(initialScore) ? [
    { key: 'x_opencti_cvss_v2_vector', value: [updatedVector] },
    { key: 'x_opencti_cvss_v2_base_score', value: [scores.base] },
    { key: 'x_opencti_cvss_v2_temporal_score', value: [isNotEmptyField(scores.temporal) ? scores.temporal : null] }
  ] : [{ key: 'x_opencti_cvss_v2_vector', value: [updatedVector] }];
  if (asObject) {
    return Object.fromEntries(result.map((e) => [e.key, e.value[0]]));
  }
  return result;
};
