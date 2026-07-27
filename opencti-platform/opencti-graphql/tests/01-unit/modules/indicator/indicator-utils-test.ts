import { describe, expect, it } from 'vitest';
import { hasSameSourceAlreadyUpdateThisScore } from '../../../../src/modules/indicator/indicator-utils';
import type { DecayHistory } from '../../../../src/modules/decayRule/decayRule-domain';

const makeHistory = (updated_by: string, score: number): DecayHistory => ({
  updated_at: new Date('2024-01-01T00:00:00Z'),
  updated_by,
  score,
});

describe('hasSameSourceAlreadyUpdateThisScore', () => {
  const sourceId = 'user-123';

  it('should return true when the same source already set the same score', () => {
    const history: DecayHistory[] = [makeHistory(sourceId, 75)];
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, history)).toBe(true);
  });

  it('should return false when source matches but score differs', () => {
    const history: DecayHistory[] = [makeHistory(sourceId, 50)];
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, history)).toBe(false);
  });

  it('should return false when score matches but source differs', () => {
    const history: DecayHistory[] = [makeHistory('other-user', 75)];
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, history)).toBe(false);
  });

  it('should return false when history is empty', () => {
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, [])).toBe(false);
  });

  it('should return true when the matching entry exists among multiple history entries', () => {
    const history: DecayHistory[] = [
      makeHistory('other-user', 75),
      makeHistory(sourceId, 50),
      makeHistory(sourceId, 75),
    ];
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, history)).toBe(true);
  });

  it('should return true when score is provided as a string matching a number stored in history', () => {
    // Le score venant du frontend peut être une string (HTML inputs)
    const history: DecayHistory[] = [makeHistory(sourceId, 75)];
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, '75' as unknown as number, history)).toBe(true);
  });

  it('should return false when score is 0 due to falsy guard in the function', () => {
    // score = 0 est falsy : la condition `if (score && ...)` empêche la recherche
    // Ce comportement est un edge case connu : un score de 0 ne sera jamais trouvé dans l'historique
    const history: DecayHistory[] = [makeHistory(sourceId, 0)];
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 0, history)).toBe(false);
  });

  it('should return false when sourceId is an empty string due to falsy guard in the function', () => {
    const history: DecayHistory[] = [makeHistory('', 75)];
    expect(hasSameSourceAlreadyUpdateThisScore('', 75, history)).toBe(false);
  });

  it('should return false when decay_history is null', () => {
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, null as unknown as DecayHistory[])).toBe(false);
  });

  it('should return false when decay_history is undefined', () => {
    expect(hasSameSourceAlreadyUpdateThisScore(sourceId, 75, undefined as unknown as DecayHistory[])).toBe(false);
  });
});

