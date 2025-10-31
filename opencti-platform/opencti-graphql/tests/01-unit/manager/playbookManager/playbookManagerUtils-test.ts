import { describe, expect, it, vi } from 'vitest';
import { isEventInPirRelationship, isValidEventType } from '../../../../src/manager/playbookManager/playbookManagerUtils';
import * as stixRelationship from '../../../../src/schema/stixRelationship';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import type { StreamDataEvent } from '../../../../src/types/event';

describe('playbookManagerUtils', () => {
  describe('isValidEventType', () => {
    describe('When evenType is correct and corresponding event in configuration is true', () => {
      it('should return true', () => {
        const result = isValidEventType('create', { create: true });
        expect(result).toBeTruthy();
      });
    });

    describe('When evenType is correct but corresponding event in configuration is false', () => {
      it('should return false', () => {
        const result = isValidEventType('create', { create: false });
        expect(result).toBeFalsy();
      });
    });
  });

  describe('isEventInPirRelationship', () => {
    describe('When scope is internal, data relationship type is relation in pir, and isStixRelation is true', () => {
      it('should return true', () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        const streamEventMock = {
          scope: 'internal',
          data: {
            relationship_type: RELATION_IN_PIR
          }
        } as unknown as StreamDataEvent;
        const result = isEventInPirRelationship(streamEventMock);
        expect(result).toBeTruthy();
      });
    });

    describe('When scope is not internal, but the rest is correct', () => {
      it('should return false', async () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        const streamEventMock = {
          scope: 'external',
          data: {
            relationship_type: RELATION_IN_PIR
          }
        } as unknown as StreamDataEvent;
        const result = await isEventInPirRelationship(streamEventMock);
        expect(result).toBeFalsy();
      });
    });

    describe('When data relationship type is not a relation in pir, but the rest is correct', () => {
      it('should return false', async () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        const streamEventMock = {
          scope: 'internal',
          data: {
            relationship_type: 'random-relationship-type'
          }
        } as unknown as StreamDataEvent;
        const result = await isEventInPirRelationship(streamEventMock);
        expect(result).toBeFalsy();
      });
    });

    describe('When isStixRelation is false, but the rest is correct', () => {
      it('should return false', async () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);
        const streamEventMock = {
          scope: 'internal',
          data: {
            relationship_type: RELATION_IN_PIR
          }
        } as unknown as StreamDataEvent;
        const result = await isEventInPirRelationship(streamEventMock);
        expect(result).toBeFalsy();
      });
    });
  });
});
