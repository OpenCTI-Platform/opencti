import { describe, expect, it } from 'vitest';
import {
  computeUserEffectiveConfidenceLevel,
  controlCreateInputWithUserConfidence,
  controlUserConfidenceAgainstElement,
  controlUpsertInputWithUserConfidence,
  adaptUpdateInputsConfidence
} from '../../../src/utils/confidence-level';
import type { AuthUser } from '../../../src/types/user';

describe('Confidence level utilities', () => {
  it('computeUserEffectiveConfidenceLevel should correctly compute the effective level', async () => {
    const makeGroup = (confidence: number | null) => ({
      id: `group_${confidence}`,
      group_confidence_level: confidence ? { max_confidence: confidence, overrides: [] } : null
    });

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
  describe('Control confidence', () => {
    const makeUser = (confidence: number | null) => ({
      id: `user_${confidence}`,
      effective_confidence_level: confidence ? { max_confidence: confidence } : null
    } as AuthUser);

    const makeObject = (confidence?: number | null) => ({
      id: `object_${confidence}`,
      entity_type: 'Report',
      confidence,
    });

    it('on any element', () => {
      expect(() => controlUserConfidenceAgainstElement(makeUser(50), makeObject(30)))
        .not.toThrowError();
      expect(() => controlUserConfidenceAgainstElement(makeUser(30), makeObject(50)))
        .toThrowError('User effective max confidence level is insufficient to update this element');
      expect(() => controlUserConfidenceAgainstElement(makeUser(50), makeObject(null)))
        .not.toThrowError();
      expect(() => controlUserConfidenceAgainstElement(makeUser(null), makeObject(30)))
        .toThrowError('User has no effective max confidence level and cannot update this element');
    });

    it('on create input', () => {
      expect(controlCreateInputWithUserConfidence(makeUser(50), makeObject(30))).toEqual({
        confidenceLevelToApply: 30,
      });
      expect(controlCreateInputWithUserConfidence(makeUser(30), makeObject(50))).toEqual({
        confidenceLevelToApply: 30,
      });
      expect(controlCreateInputWithUserConfidence(makeUser(30), makeObject(null))).toEqual({
        confidenceLevelToApply: 30,
      });
      expect(() => controlCreateInputWithUserConfidence(makeUser(null), makeObject(50)))
        .toThrowError('User has no effective max confidence level and cannot create this element');
    });

    it('on upsert input', () => {
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeObject(30), makeObject(10)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeObject(10), makeObject(30)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeObject(50), makeObject(10)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeObject(10), makeObject(50)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(10), makeObject(50), makeObject(30)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(10), makeObject(30), makeObject(50)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 10,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeObject(null), makeObject(30)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 50,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeObject(null), makeObject(50)))
        .toEqual({
          isConfidenceMatch: false,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(50), makeObject(30), makeObject(null)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeObject(50), makeObject(null)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(controlUpsertInputWithUserConfidence(makeUser(30), makeObject(null), makeObject(null)))
        .toEqual({
          isConfidenceMatch: true,
          confidenceLevelToApply: 30,
        });
      expect(() => controlUpsertInputWithUserConfidence(makeUser(null), makeObject(30), makeObject(50)))
        .toThrowError('User has no effective max confidence level and cannot update this element');
    });

    it('', () => {
      const makeConfidenceInput = (confidence: number) => ({
        key: 'confidence',
        value: [confidence.toString()],
      });
      adaptUpdateInputsConfidence(makeUser(50), makeConfidenceInput(10), makeObject(30));
    });
  });
});
