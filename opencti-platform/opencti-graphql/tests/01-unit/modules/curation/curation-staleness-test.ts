import { describe, expect, it } from 'vitest';
import { isDecayedToRevocation } from '../../../../src/modules/curation/curation-detectors';

const indicator = (score: unknown, revokeScore?: unknown) => ({
  x_opencti_score: score,
  decay_applied_rule: revokeScore === undefined ? undefined : { decay_revoke_score: revokeScore },
});

describe('decayed indicators', () => {
  it('are due for revocation once their score reaches the revoke score, as the decay manager decides', () => {
    expect(isDecayedToRevocation(indicator(19, 20))).toBe(true);
    expect(isDecayedToRevocation(indicator(20, 20))).toBe(true);
    expect(isDecayedToRevocation(indicator(21, 20))).toBe(false);
  });

  it('are never due without a decay rule or a score', () => {
    expect(isDecayedToRevocation(indicator(10))).toBe(false);
    expect(isDecayedToRevocation(indicator(undefined, 20))).toBe(false);
    expect(isDecayedToRevocation(indicator('10', 20))).toBe(false);
  });
});
