import { describe, expect, it } from 'vitest';
import { computeUserEffectiveConfidenceLevel, cropMaxConfidenceInEditValue } from '../../../src/utils/confidence-level';
import type { AuthUser } from '../../../src/types/user';
import { FunctionalError } from '../../../src/config/errors';

describe('Confidence level utilities', () => {
  it('sanitizeConfidenceInEditInput should crop value with various min/max inputs', () => {
    // complete object
    expect(cropMaxConfidenceInEditValue({ max_confidence: 50, overrides: [] })).toEqual({ max_confidence: 50, overrides: [] });
    expect(cropMaxConfidenceInEditValue({ max_confidence: 300, overrides: [] })).toEqual({ max_confidence: 100, overrides: [] });
    expect(cropMaxConfidenceInEditValue({ max_confidence: -300, overrides: [] })).toEqual({ max_confidence: 0, overrides: [] });
    expect(cropMaxConfidenceInEditValue({ max_confidence: -300, overrides: [{ entity_type: 'Report', max_confidence: 50 }] }))
      .toEqual({ max_confidence: 0, overrides: [{ entity_type: 'Report', max_confidence: 50 }] });
    expect(cropMaxConfidenceInEditValue({ max_confidence: 50, overrides: [{ entity_type: 'Report', max_confidence: 500 }] }))
      .toEqual({ max_confidence: 50, overrides: [{ entity_type: 'Report', max_confidence: 100 }] });
    expect(cropMaxConfidenceInEditValue({ max_confidence: 50, overrides: [{ entity_type: 'Report', max_confidence: -500 }] }))
      .toEqual({ max_confidence: 50, overrides: [{ entity_type: 'Report', max_confidence: 0 }] });

    expect(cropMaxConfidenceInEditValue({
      max_confidence: -50,
      overrides: [
        { entity_type: 'Report', max_confidence: 90 },
        { entity_type: 'Malware', max_confidence: -10 },
        { entity_type: 'Note', max_confidence: 45 },
        { entity_type: 'Pokemon', max_confidence: 10000 },
      ]
    })).toEqual({
      max_confidence: 0,
      overrides: [
        { entity_type: 'Report', max_confidence: 90 },
        { entity_type: 'Malware', max_confidence: 0 },
        { entity_type: 'Note', max_confidence: 45 },
        { entity_type: 'Pokemon', max_confidence: 100 },
      ]
    });

    // complete overrides object
    expect(cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: 50 }, '/group_confidence_level/overrides/0'))
      .toEqual({ entity_type: 'Report', max_confidence: 50 });
    expect(cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: 300 }, '/group_confidence_level/overrides/8'))
      .toEqual({ entity_type: 'Report', max_confidence: 100 });
    expect(cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: -300 }, '/group_confidence_level/overrides/7'))
      .toEqual({ entity_type: 'Report', max_confidence: 0 });
    expect(cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: 50 }, '/user_confidence_level/overrides/0'))
      .toEqual({ entity_type: 'Report', max_confidence: 50 });
    expect(cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: 300 }, '/user_confidence_level/overrides/5'))
      .toEqual({ entity_type: 'Report', max_confidence: 100 });
    expect(cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: -300 }, '/user_confidence_level/overrides/3'))
      .toEqual({ entity_type: 'Report', max_confidence: 0 });

    // max_confidence only
    expect(cropMaxConfidenceInEditValue(50, '/group_confidence_level/max_confidence')).toEqual(50);
    expect(cropMaxConfidenceInEditValue(300, '/group_confidence_level/max_confidence')).toEqual(100);
    expect(cropMaxConfidenceInEditValue(-300, '/group_confidence_level/max_confidence')).toEqual(0);
    expect(cropMaxConfidenceInEditValue(50, '/user_confidence_level/max_confidence')).toEqual(50);
    expect(cropMaxConfidenceInEditValue(300, '/user_confidence_level/max_confidence')).toEqual(100);
    expect(cropMaxConfidenceInEditValue(-300, '/user_confidence_level/max_confidence')).toEqual(0);

    // overrides.max_confidence only
    expect(cropMaxConfidenceInEditValue(50, '/group_confidence_level/overrides/0/max_confidence')).toEqual(50);
    expect(cropMaxConfidenceInEditValue(300, '/group_confidence_level/overrides/78/max_confidence')).toEqual(100);
    expect(cropMaxConfidenceInEditValue(-300, '/group_confidence_level/overrides/9/max_confidence')).toEqual(0);
    expect(cropMaxConfidenceInEditValue(50, '/user_confidence_level/overrides/8/max_confidence')).toEqual(50);
    expect(cropMaxConfidenceInEditValue(300, '/user_confidence_level/overrides/0/max_confidence')).toEqual(100);
    expect(cropMaxConfidenceInEditValue(-300, '/user_confidence_leve/overrides/41/max_confidence')).toEqual(0);

    // throw error properly if patch is incorrect
    expect(() => cropMaxConfidenceInEditValue(-300, '/user_confidence_leve/wrongkey/41/max_confidence'))
      .toThrowError(FunctionalError(
        'Unhandled object_path for patching a confidence level',
        { object_path: '/user_confidence_level/wrongkey/41/max_confidence', value: -300 }
      ));
    expect(() => cropMaxConfidenceInEditValue({ entity_type: 'Report', max_confidence: 50 }, '/group_confidence_level/overrides/0/max_confidence'))
      .toThrowError(FunctionalError(
        'Cannot crop non-finite input value',
        { value: { entity_type: 'Report', max_confidence: 50 } }
      ));
  });

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
