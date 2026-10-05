import { describe, expect, it } from 'vitest';
import { indicatorRevocationTime, isDuplicateDetectionEnabled, observablesActiveSinceRevocation } from '../../../../src/modules/curation/curation-detectors';
import type { CurationSettings } from '../../../../src/modules/curation/curation-types';

const settings = (enabled: string[], curationEnabled = true) => ({ curation_enabled: curationEnabled, enabled_detectors: enabled }) as unknown as CurationSettings;

describe('duplicate detection switches', () => {
  it('looks for duplicates while one of the name normalization, similarity or behavior detectors is on', () => {
    expect(isDuplicateDetectionEnabled(settings(['normalization']))).toBe(true);
    expect(isDuplicateDetectionEnabled(settings(['similarity', 'staleness']))).toBe(true);
    expect(isDuplicateDetectionEnabled(settings(['behavior']))).toBe(true);
  });

  it('does no duplicate work with the three off or curation disabled', () => {
    expect(isDuplicateDetectionEnabled(settings(['contradiction', 'staleness', 'relationship_conflict']))).toBe(false);
    expect(isDuplicateDetectionEnabled(settings([]))).toBe(false);
    expect(isDuplicateDetectionEnabled(settings(['normalization'], false))).toBe(false);
  });
});

describe('revocation time of an indicator', () => {
  const revokedManually = { revoked: true, valid_until: '2026-03-01T00:00:00.000Z', updated_at: '2026-06-01T00:00:00.000Z' };

  it('is not moved by an edit made after the revocation', () => {
    expect(indicatorRevocationTime(revokedManually)).toBe(new Date('2026-03-01T00:00:00.000Z').getTime());
    const observable = { internal_id: 'observable-id', updated_at: '2026-04-01T00:00:00.000Z', x_opencti_score: 80 };
    expect(observablesActiveSinceRevocation(revokedManually, [observable])).toEqual([observable]);
  });

  it('is the point at the revoke score of a decay revocation, the latest one when revoked again', () => {
    const decayed = {
      revoked: true,
      valid_until: '2099-01-01T00:00:00.000Z',
      updated_at: '2026-06-01T00:00:00.000Z',
      decay_applied_rule: { decay_revoke_score: 20 },
      decay_history: [
        { score: 10, updated_at: '2026-01-01T00:00:00.000Z' },
        { score: 80, updated_at: '2026-02-01T00:00:00.000Z' },
        { score: 20, updated_at: '2026-04-01T00:00:00.000Z' },
      ],
    };
    expect(indicatorRevocationTime(decayed)).toBe(new Date('2026-04-01T00:00:00.000Z').getTime());
  });

  it('falls back on the last update when nothing else tells', () => {
    expect(indicatorRevocationTime({ revoked: true, updated_at: '2026-06-01T00:00:00.000Z' })).toBe(new Date('2026-06-01T00:00:00.000Z').getTime());
  });
});
