import { hashSHA256 } from '../../utils/hash';

const FINGERPRINT_LENGTH = 32;

const sortedUnique = (values: string[]) => [...new Set(values)].sort();

/**
 * Fingerprint of a procedure: sha256 hex (utf8) of
 * "technique ids :: platforms :: mitre-attack phase names", each part deduplicated, sorted and joined by "|".
 * The pycti implementation must produce the same value byte for byte.
 */
export const computeProcedureFingerprint = (techniqueIds: string[], platforms: string[], phaseNames: string[]): string => {
  const material = [techniqueIds, platforms, phaseNames].map((part) => sortedUnique(part).join('|')).join('::');
  return hashSHA256(material).slice(0, FINGERPRINT_LENGTH);
};
