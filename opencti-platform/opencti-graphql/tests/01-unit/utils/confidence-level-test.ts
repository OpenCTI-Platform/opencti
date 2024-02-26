import { describe, expect, it } from 'vitest';
import {
  adaptFiltersWithUserConfidence,
  adaptUpdateInputsConfidence,
  computeUserEffectiveConfidenceLevel,
  controlCreateInputWithUserConfidence,
  controlUpsertInputWithUserConfidence,
  controlUserConfidenceAgainstElement
} from '../../../src/utils/confidence-level';
import type { AuthUser } from '../../../src/types/user';
import { type FilterGroup, FilterMode, FilterOperator } from '../../../src/generated/graphql';
import { BYPASS } from '../../../src/utils/access';

const makeUser = (confidence: number | null) => ({
  id: `user_${confidence}`,
  effective_confidence_level: confidence ? { max_confidence: confidence } : null
} as AuthUser);

const makeGroup = (confidence: number | null) => ({
  id: `group_${confidence}`,
  group_confidence_level: confidence ? { max_confidence: confidence, overrides: [] } : null
});

const makeElement = (confidence?: number | null) => ({
  id: `object_${confidence}`,
  entity_type: 'Report',
  confidence,
});

describe('Confidence level utilities', () => {
  it('computeUserEffectiveConfidenceLevel should correctly compute the effective level', async () => {
    const group70 = makeGroup(70);
    const group80 = makeGroup(80);
    const groupNull = makeGroup(null);

    // minimal subset of a real User
    const userA = {
      id: 'userA',
      user_confidence_level: {
        max_confidence: 30,
        overrides: [],
      },
      groups: [group70, group80],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userA as unknown as AuthUser)).toEqual({
      max_confidence: 30,
      overrides: [],
      source: { type: 'User', object: userA },
    });

    const userB = {
      id: 'userB',
      user_confidence_level: null,
      groups: [group70, group80],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userB as unknown as AuthUser)).toEqual({
      max_confidence: 80,
      overrides: [],
      source: { type: 'Group', object: group80 },
    });

    const userC = {
      user_confidence_level: null,
      groups: [groupNull, group70, groupNull],
      capabilities: [],
    };
    expect(computeUserEffectiveConfidenceLevel(userC as unknown as AuthUser)).toEqual({
      max_confidence: 70,
      overrides: [],
      source: { type: 'Group', object: group70 },
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
      overrides: [],
      source: { type: 'Bypass' },
    });

    const userG = {
      user_confidence_level: null,
      groups: [group70, group80],
      capabilities: [{ name: BYPASS }],
    };
    expect(computeUserEffectiveConfidenceLevel(userG as unknown as AuthUser)).toEqual({
      max_confidence: 100,
      overrides: [],
      source: { type: 'Bypass' },
    });
  });

  describe('Control confidence', () => {
    it('on any element', () => {
      expect(() => controlUserConfidenceAgainstElement(makeUser(50), makeElement(30)))
        .not.toThrowError();
      expect(() => controlUserConfidenceAgainstElement(makeUser(30), makeElement(50)))
        .toThrowError('User effective max confidence level is insufficient to update this element');
      expect(() => controlUserConfidenceAgainstElement(makeUser(50), makeElement(null)))
        .not.toThrowError();
      expect(() => controlUserConfidenceAgainstElement(makeUser(null), makeElement(30)))
        .toThrowError('User has no effective max confidence level and cannot update this element');
      expect(() => controlUserConfidenceAgainstElement(makeUser(50), {
        id: 'object_no_confidence',
        entity_type: 'Artifact',
      })).not.toThrowError();
      expect(() => controlUserConfidenceAgainstElement(makeUser(null), {
        id: 'object_no_confidence',
        entity_type: 'Artifact',
      })).not.toThrowError(); // existence of user level is not even checked
    });
    it('on any element (noThrow)', () => {
      expect(controlUserConfidenceAgainstElement(makeUser(50), makeElement(30), true)).toEqual(true);
      expect(controlUserConfidenceAgainstElement(makeUser(30), makeElement(50), true)).toEqual(false);
      expect(controlUserConfidenceAgainstElement(makeUser(50), makeElement(null), true)).toEqual(true);
      expect(controlUserConfidenceAgainstElement(makeUser(null), makeElement(30), true)).toEqual(false);
      expect(controlUserConfidenceAgainstElement(makeUser(50), { id: 'object_no_confidence', entity_type: 'Artifact' }, true)).toEqual(true);
      expect(controlUserConfidenceAgainstElement(makeUser(null), { id: 'object_no_confidence', entity_type: 'Artifact' }, true)).toEqual(true);
    });
    it('on create input', () => {
      expect(controlCreateInputWithUserConfidence(makeUser(50), makeElement(30))).toEqual({
        confidenceLevelToApply: 30,
      });
      expect(controlCreateInputWithUserConfidence(makeUser(30), makeElement(50))).toEqual({
        confidenceLevelToApply: 30,
      });
      expect(controlCreateInputWithUserConfidence(makeUser(30), makeElement(null))).toEqual({
        confidenceLevelToApply: 30,
      });
      expect(() => controlCreateInputWithUserConfidence(makeUser(null), makeElement(50)))
        .toThrowError('User has no effective max confidence level and cannot create this element');
    });
    it('on upsert input', () => {
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeElement(30), makeElement(10)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeElement(10), makeElement(30)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeElement(50), makeElement(10)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeElement(10), makeElement(50)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(10), makeElement(50), makeElement(30)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(10), makeElement(30), makeElement(50)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeElement(null), makeElement(30)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 50,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeElement(null), makeElement(50)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeElement(30), makeElement(null)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeElement(50), makeElement(null)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeElement(null), makeElement(null)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(() => controlUpsertInputWithUserConfidence(makeUser(null), makeElement(30), makeElement(50)))
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

    expect(adaptUpdateInputsConfidence(makeUser(50), makeConfidenceInput(30), makeElement(10)))
      .toEqual([{ key: 'confidence', value: ['30'] }]);
    expect(adaptUpdateInputsConfidence(makeUser(50), makeConfidenceInput(10), makeElement(30)))
      .toEqual([{ key: 'confidence', value: ['10'] }]);
    expect(adaptUpdateInputsConfidence(makeUser(30), makeConfidenceInput(50), makeElement(10)))
      .toEqual([{ key: 'confidence', value: ['30'] }]); // capped
    expect(adaptUpdateInputsConfidence(makeUser(30), makeConfidenceInput(10), makeElement(50)))
      .toEqual([{ key: 'confidence', value: ['10'] }]); // this function does not control against element!
    expect(adaptUpdateInputsConfidence(makeUser(10), makeConfidenceInput(50), makeElement(30)))
      .toEqual([{ key: 'confidence', value: ['10'] }]); // capped / this function does not control against element!
    expect(adaptUpdateInputsConfidence(makeUser(10), makeConfidenceInput(30), makeElement(50)))
      .toEqual([{ key: 'confidence', value: ['10'] }]); // capped / this function does not control against element!
    expect(adaptUpdateInputsConfidence(makeUser(10), otherInput, makeElement(50)))
      .toEqual([otherInput]); // no need to inject confidence
    expect(adaptUpdateInputsConfidence(makeUser(10), otherInput, makeElement(null)))
      .toEqual([otherInput, { key: 'confidence', value: ['10'] }]); // inject user's confidence
    expect(adaptUpdateInputsConfidence(makeUser(10), makeConfidenceInput(30), makeElement(null)))
      .toEqual([{ key: 'confidence', value: ['10'] }]); // capped / no need to inject user's confidence
  });

  it('getConfidenceFilterForUser shall produce correct filters', () => {
    const emptyFilterGroup: FilterGroup = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [],
    };
    const exampleFilterGroup: FilterGroup = {
      mode: FilterMode.Or,
      filterGroups: [],
      filters: [
        { key: ['name'], operator: FilterOperator.Contains, mode: FilterMode.Or, values: ['aa', 'bb', 'cc'] },
        { key: ['score'], operator: FilterOperator.Gte, mode: FilterMode.And, values: [70] }
      ],
    };
    const injectedFilters: FilterGroup = {
      mode: FilterMode.Or,
      filterGroups: [],
      filters: [
        {
          key: ['entity_type'],
          operator: FilterOperator.NotEq,
          values: ['Stix-Domain-Object', 'Stix-Relationship'],
        },
        {
          key: ['confidence'],
          operator: FilterOperator.Lte,
          values: [50],
        },
        {
          key: ['confidence'],
          operator: FilterOperator.Nil,
          values: [],
        },
      ],
    };

    expect(adaptFiltersWithUserConfidence(makeUser(50), emptyFilterGroup))
      .toEqual({
        mode: FilterMode.And,
        filters: [],
        filterGroups: [injectedFilters]
      });
    expect(adaptFiltersWithUserConfidence(makeUser(50), exampleFilterGroup))
      .toEqual({
        mode: FilterMode.And,
        filters: [],
        filterGroups: [injectedFilters, exampleFilterGroup]
      });
  });
});
