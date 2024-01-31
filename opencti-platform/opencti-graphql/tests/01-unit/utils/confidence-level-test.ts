import { describe, expect, it } from 'vitest';
import { computeUserEffectiveConfidenceLevel } from '../../../src/utils/confidence-level';
import type { AuthUser } from '../../../src/types/user';

describe('Confidence level utilities', () => {
  it('computeUserEffectiveConfidenceLevel should correctly compute the effective level', async () => {
    const group70 = {
      id: 'group70',
      group_confidence_level: {
        max_confidence: 70,
        overrides: [],
      }
    };

    const group80 = {
      id: 'group80',
      group_confidence_level: {
        max_confidence: 70,
        overrides: [],
      }
    };

    const groupNull = {
      id: 'groupNull',
      group_confidence_level: null
    };

    // minimal subset of a real User
    const userA = {
      id: 'userA',
      user_confidence_level: {
        max_confidence: 30,
        overrides: [],
      },
      groups: [group70, group80],
    };
    expect(computeUserEffectiveConfidenceLevel(userA as unknown as AuthUser)).toEqual({
      max_confidence: 30,
      overrides: [],
      source: userA,
    });

    const userB = {
      id: 'userB',
      user_confidence_level: null,
      groups: [group70, group80],
    };
    expect(computeUserEffectiveConfidenceLevel(userB as unknown as AuthUser)).toEqual({
      max_confidence: 70,
      overrides: [],
      source: group70,
    });

    const userC = {
      user_confidence_level: null,
      groups: [groupNull, group70, groupNull],
    };
    expect(computeUserEffectiveConfidenceLevel(userC as unknown as AuthUser)).toEqual({
      max_confidence: 70,
      overrides: [],
      source: group70,
    });

    const userD = {
      user_confidence_level: null,
      groups: [groupNull, groupNull],
    };
    expect(computeUserEffectiveConfidenceLevel(userD as unknown as AuthUser)).toBeNull();

    const userE = {
      user_confidence_level: null,
      groups: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userE as unknown as AuthUser)).toBeNull();
  });
});
