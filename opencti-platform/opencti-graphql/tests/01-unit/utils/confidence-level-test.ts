import { describe, expect, it } from 'vitest';
import {
  adaptUpdateInputsConfidence,
  computeUserEffectiveConfidenceLevel,
  controlCreateInputWithUserConfidence,
  controlUpsertInputWithUserConfidence,
  controlUserConfidenceAgainstElement
} from '../../../src/utils/confidence-level';
import type { AuthUser } from '../../../src/types/user';
import { BYPASS } from '../../../src/utils/access';

const makeUser = (confidence: number | null) => ({
  id: `user_${confidence}`,
  effective_confidence_level: confidence ? { max_confidence: confidence } : null
} as AuthUser);

const makeGroup = (confidence: number | null) => ({
  id: `group_${confidence}`,
  group_confidence_level: confidence ? { max_confidence: confidence, overrides: [] } : null
});

const makeGroupWithOverrides = (confidence: number | null, overrides: { entity_type: string, max_confidence: number }[] | null) => ({
  id: `group_${confidence}`,
  group_confidence_level: confidence ? { max_confidence: confidence, overrides } : null,
});

const makeUserWithOverrides = (confidence: number | null, overrides: { entity_type: string, max_confidence: number }[] | null) => ({
  id: `user_${confidence}`,
  effective_confidence_level: {
    max_confidence: confidence ?? null,
    overrides: overrides ?? [],
  }
} as AuthUser);

const makeReport = (confidence?: number | null) => ({
  id: `object_${confidence}`,
  entity_type: 'Report',
  confidence,
});

describe('Confidence level utilities', () => {
  it('computeUserEffectiveConfidenceLevel should correctly compute the effective level', async () => {
    const groupNull = makeGroup(null);
    const group70 = makeGroup(70);
    const group80 = makeGroup(80);
    const group40WithReport90 = makeGroupWithOverrides(40, [{ entity_type: 'Report', max_confidence: 90 }]);
    const group40WithOverrides = makeGroupWithOverrides(
      40,
      [{ entity_type: 'Report', max_confidence: 90 }, { entity_type: 'Case-Rfi', max_confidence: 20 }]
    );

    // minimal subset of a real User
    const userA = {
      id: 'userA',
      user_confidence_level: {
        max_confidence: 30,
        overrides: [{ entity_type: 'Malware', max_confidence: 70 }],
      },
      groups: [group70, group80],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userA as unknown as AuthUser)).toEqual({
      max_confidence: 30,
      source: { type: 'User', object: userA },
      overrides: [{ entity_type: 'Malware', max_confidence: 70 }],
    });

    const userB = {
      id: 'userB',
      user_confidence_level: null,
      groups: [group70, group80],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userB as unknown as AuthUser)).toEqual({
      max_confidence: 80,
      source: { type: 'Group', object: group80 },
      overrides: [],
    });

    const userC = {
      user_confidence_level: null,
      groups: [groupNull, group70, groupNull],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userC as unknown as AuthUser)).toEqual({
      max_confidence: 70,
      source: { type: 'Group', object: group70 },
      overrides: [],
    });

    const userD = {
      user_confidence_level: null,
      groups: [groupNull, groupNull],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userD as unknown as AuthUser)).toBeNull();

    const userE = {
      user_confidence_level: null,
      groups: [],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userE as unknown as AuthUser)).toBeNull();

    const userF = {
      user_confidence_level: {
        max_confidence: 30,
        overrides: [],
      },
      groups: [group70],
      capabilities: [{ name: BYPASS }],
    };
    expect(computeUserEffectiveConfidenceLevel(userF as unknown as AuthUser)).toEqual({
      max_confidence: 100,
      source: { type: 'Bypass' },
      overrides: [],
    });

    const userG = {
      user_confidence_level: null,
      groups: [group70, group80],
      capabilities: [{ name: BYPASS }],
    };
    expect(computeUserEffectiveConfidenceLevel(userG as unknown as AuthUser)).toEqual({
      max_confidence: 100,
      source: { type: 'Bypass' },
      overrides: [],
    });
    const userH = {
      user_confidence_level: null,
      groups: [group40WithReport90],
      capabilities: []
    };
    expect(computeUserEffectiveConfidenceLevel(userH as unknown as AuthUser)).toEqual({
      max_confidence: 40,
      source: { type: 'Group', object: group40WithReport90 },
      overrides: [{ entity_type: 'Report', max_confidence: 90 }],
    });

    const userI = {
      user_confidence_level: {
        max_confidence: 30,
        overrides: [],
      },
      groups: [group40WithReport90],
      capabilities: []
    };
    expect(computeUserEffectiveConfidenceLevel(userI as unknown as AuthUser)).toEqual({
      max_confidence: 30,
      source: { type: 'User', object: userI },
      overrides: [{ entity_type: 'Report', max_confidence: 90 }],
    });

    const userJ = {
      user_confidence_level: {
        max_confidence: null,
        overrides: [{ entity_type: 'Report', max_confidence: 50 }, { entity_type: 'Malware', max_confidence: 35 }],
      },
      groups: [group70, group40WithOverrides],
      capabilities: []
    };
    expect(computeUserEffectiveConfidenceLevel(userJ as unknown as AuthUser)).toEqual({
      max_confidence: 70, // biggest values among the groups
      source: { type: 'Group', object: group70 },
      overrides: [
        { entity_type: 'Report', max_confidence: 50 }, // from user, overwrites the Report override of group40WithOverrides
        { entity_type: 'Case-Rfi', max_confidence: 20 }, // from group40WithOverrides
        { entity_type: 'Malware', max_confidence: 35 } // from user's overrides
      ],
    });

    const userK = {
      user_confidence_level: {
        max_confidence: null,
        overrides: [{ entity_type: 'Report', max_confidence: 50 }, { entity_type: 'Malware', max_confidence: 35 }],
      },
      groups: [groupNull, groupNull],
      capabilities: []
    };
    expect(computeUserEffectiveConfidenceLevel(userK as unknown as AuthUser)).toEqual(null);
  });
});

describe('Control confidence', () => {
  it('on any element', () => {
    expect(() => controlUserConfidenceAgainstElement(makeUser(50), makeReport(30)))
      .not.toThrowError();
    expect(() => controlUserConfidenceAgainstElement(makeUser(30), makeReport(50)))
      .toThrowError('User effective max confidence level is insufficient to update this element');
    expect(() => controlUserConfidenceAgainstElement(makeUser(50), makeReport(null)))
      .not.toThrowError();
    expect(() => controlUserConfidenceAgainstElement(makeUser(null), makeReport(30)))
      .toThrowError('User has no effective max confidence level and cannot update this element');
    expect(() => controlUserConfidenceAgainstElement(makeUser(50), {
      id: 'object_no_confidence',
      entity_type: 'Artifact',
    })).not.toThrowError();
    expect(() => controlUserConfidenceAgainstElement(makeUser(null), {
      id: 'object_no_confidence',
      entity_type: 'Artifact',
    })).not.toThrowError(); // existence of user level is not even checked
    expect(() => controlUserConfidenceAgainstElement(
      makeUserWithOverrides(40, [{ entity_type: 'Report', max_confidence: 90 }]),
      makeReport(80),
    )).not.toThrowError();
    expect(() => controlUserConfidenceAgainstElement(makeUserWithOverrides(40, null), makeReport(100)))
      .toThrowError('User effective max confidence level is insufficient to update this element');
    expect(() => controlUserConfidenceAgainstElement(makeUserWithOverrides(null, null), makeReport(80)))
      .toThrowError('User has no effective max confidence level and cannot update this element');
  });
  it('on any element (noThrow)', () => {
    expect(controlUserConfidenceAgainstElement(makeUser(50), makeReport(30), true)).toEqual(true);
    expect(controlUserConfidenceAgainstElement(makeUser(30), makeReport(50), true)).toEqual(false);
    expect(controlUserConfidenceAgainstElement(makeUser(50), makeReport(null), true)).toEqual(true);
    expect(controlUserConfidenceAgainstElement(makeUser(null), makeReport(30), true)).toEqual(false);
    expect(controlUserConfidenceAgainstElement(makeUser(50), { id: 'object_no_confidence', entity_type: 'Artifact' }, true)).toEqual(true);
    expect(controlUserConfidenceAgainstElement(makeUser(null), { id: 'object_no_confidence', entity_type: 'Artifact' }, true)).toEqual(true);
  });
  it('on create input', () => {
    expect(controlCreateInputWithUserConfidence(makeUser(50), makeReport(30), 'Report')).toEqual({
      confidenceLevelToApply: 30,
    });
    expect(controlCreateInputWithUserConfidence(makeUser(30), makeReport(50), 'Report')).toEqual({
      confidenceLevelToApply: 30,
    });
    expect(controlCreateInputWithUserConfidence(makeUser(30), makeReport(null), 'Report')).toEqual({
      confidenceLevelToApply: 30,
    });
    expect(controlCreateInputWithUserConfidence(
      makeUserWithOverrides(40, [{ entity_type: 'Report', max_confidence: 90 }]),
      makeReport(null),
      'Report'
    )).toEqual({ confidenceLevelToApply: 90, });
    expect(controlCreateInputWithUserConfidence(
      makeUserWithOverrides(80, [{ entity_type: 'Report', max_confidence: 10 }]),
      makeReport(null),
      'Report'
    )).toEqual({ confidenceLevelToApply: 10, });
    expect(controlCreateInputWithUserConfidence(
      makeUserWithOverrides(30, [{ entity_type: 'Malware', max_confidence: 90 }]),
      makeReport(null),
      'Report'
    )).toEqual({ confidenceLevelToApply: 30, });
    expect(controlCreateInputWithUserConfidence(
      makeUserWithOverrides(null, [{ entity_type: 'Report', max_confidence: 90 }]),
      makeReport(null),
      'Report'
    )).toEqual({ confidenceLevelToApply: 90, });
    expect(() => controlCreateInputWithUserConfidence(makeUser(null), makeReport(50), 'Report'))
      .toThrowError('User has no effective max confidence level and cannot create this element');
  });
  it('on upsert input', () => {
    expect(controlUpsertInputWithUserConfidence(makeUser(50), makeReport(30), makeReport(10)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 30,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(50), makeReport(10), makeReport(30)))
      .toEqual({
        isConfidenceMatch: false,
        confidenceLevelToApply: 10,
        isConfidenceUpper: false,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(30), makeReport(50), makeReport(10)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 30,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(30), makeReport(10), makeReport(50)))
      .toEqual({
        isConfidenceMatch: false,
        confidenceLevelToApply: 10,
        isConfidenceUpper: false,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(10), makeReport(50), makeReport(30)))
      .toEqual({
        isConfidenceMatch: false,
        confidenceLevelToApply: 10,
        isConfidenceUpper: false,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(10), makeReport(30), makeReport(50)))
      .toEqual({
        isConfidenceMatch: false,
        confidenceLevelToApply: 10,
        isConfidenceUpper: false,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(50), makeReport(null), makeReport(30)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 50,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(30), makeReport(null), makeReport(50)))
      .toEqual({
        isConfidenceMatch: false,
        confidenceLevelToApply: 30,
        isConfidenceUpper: false,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(50), makeReport(30), makeReport(null)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 30,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(30), makeReport(50), makeReport(null)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 30,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUser(30), makeReport(null), makeReport(null)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 30,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUserWithOverrides(40, [{ entity_type: 'Report', max_confidence: 80 }]), makeReport(null), makeReport(null)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 80,
        isConfidenceUpper: true,
      });
    expect(controlUpsertInputWithUserConfidence(makeUserWithOverrides(null, [{ entity_type: 'Report', max_confidence: 80 }]), makeReport(null), makeReport(null)))
      .toEqual({
        isConfidenceMatch: true,
        confidenceLevelToApply: 80,
        isConfidenceUpper: true,
      });
    expect(() => controlUpsertInputWithUserConfidence(makeUser(null), makeReport(30), makeReport(50)))
      .toThrowError('User has no effective max confidence level and cannot upsert this element');
  });
});

it('adaptUpdateInputsConfidence should adapt correctly input payload', () => {
  const makeConfidenceInput = (confidence: number) => ({
    key: 'confidence',
    value: [confidence.toString()],
  });
  const otherInput = {
    key: 'description',
    value: ['some text'],
  };

  expect(adaptUpdateInputsConfidence(makeUser(50), makeConfidenceInput(30), makeReport(10)))
    .toEqual([{ key: 'confidence', value: ['30'] }]);
  expect(adaptUpdateInputsConfidence(makeUser(50), makeConfidenceInput(10), makeReport(30)))
    .toEqual([{ key: 'confidence', value: ['10'] }]);
  expect(adaptUpdateInputsConfidence(makeUser(30), makeConfidenceInput(50), makeReport(10)))
    .toEqual([{ key: 'confidence', value: ['30'] }]); // capped
  expect(adaptUpdateInputsConfidence(makeUser(30), makeConfidenceInput(10), makeReport(50)))
    .toEqual([{ key: 'confidence', value: ['10'] }]); // this function does not control against element!
  expect(adaptUpdateInputsConfidence(makeUser(10), makeConfidenceInput(50), makeReport(30)))
    .toEqual([{ key: 'confidence', value: ['10'] }]); // capped / this function does not control against element!
  expect(adaptUpdateInputsConfidence(makeUser(10), makeConfidenceInput(30), makeReport(50)))
    .toEqual([{ key: 'confidence', value: ['10'] }]); // capped / this function does not control against element!
  expect(adaptUpdateInputsConfidence(makeUser(10), otherInput, makeReport(50)))
    .toEqual([otherInput]); // no need to inject confidence
  expect(adaptUpdateInputsConfidence(makeUser(10), otherInput, makeReport(null)))
    .toEqual([otherInput, { key: 'confidence', value: ['10'] }]); // inject user's confidence
  expect(adaptUpdateInputsConfidence(makeUser(10), makeConfidenceInput(30), makeReport(null)))
    .toEqual([{ key: 'confidence', value: ['10'] }]); // capped / no need to inject user's confidence
});
