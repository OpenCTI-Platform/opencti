import { describe, expect, it } from 'vitest';
import { computeProcedureFingerprint } from '../../../src/modules/procedure/procedure-fingerprint';

const ATTACK_PATTERN_A = 'attack-pattern--e94e1030-0b72-4b37-ab03-00e1a81a665e';
const ATTACK_PATTERN_B = 'attack-pattern--4c209832-0086-42bf-b4ac-84cdc2434a72';

describe('computeProcedureFingerprint', () => {
  it('matches the shared fingerprint vector', () => {
    expect(computeProcedureFingerprint(
      [ATTACK_PATTERN_A, ATTACK_PATTERN_B],
      ['windows'],
      ['execution', 'defense-evasion'],
    )).toBe('a85ef1be299c2196e535393a59df5021');
  });

  it('is order-independent and deduplicates', () => {
    const expected = computeProcedureFingerprint(
      [ATTACK_PATTERN_A, ATTACK_PATTERN_B],
      ['windows', 'linux'],
      ['execution', 'defense-evasion'],
    );
    expect(computeProcedureFingerprint(
      [ATTACK_PATTERN_B, ATTACK_PATTERN_A, ATTACK_PATTERN_B],
      ['linux', 'windows', 'linux'],
      ['defense-evasion', 'execution', 'execution'],
    )).toBe(expected);
  });

  it('handles empty inputs', () => {
    expect(computeProcedureFingerprint([], [], [])).toBe('d00d9be38948fb145335e663ae2d01c0');
  });
});
