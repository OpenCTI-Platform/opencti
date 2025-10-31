import { describe, expect, it, vi } from 'vitest';
import { isEventInPir, isValidEventType } from '../../../../src/manager/playbookManager/playbookManagerUtils';
import type { StreamDataEvent } from '../../../../src/types/event';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import * as stixRelationship from '../../../../src/schema/stixRelationship';

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

      describe('When evenType is not correct, even if all events in configuration are true', () => {
        it('should return false', () => {
          const result = isValidEventType('random-event-type', {
            update: true,
            create: true,
            delete: true });
          expect(result).toBeFalsy();
        });
      });
    });
  });

  describe('isEventInPir', () => {
    describe('When scope is internal, data relationship type is relation in pir, and isStixRelation is true', () => {
      it('should return true', () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        const streamEventMock = {
          scope: 'internal',
          data: {
            relationship_type: RELATION_IN_PIR
          }
        } as unknown as StreamDataEvent;
        const result = isEventInPir(streamEventMock);
        expect(result).toBeTruthy();
      });
    });

    describe('When scope is not internal, but the rest is correct', () => {
      it('should return false', () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        const streamEventMock = {
          scope: 'external',
          data: {
            relationship_type: RELATION_IN_PIR
          }
        } as unknown as StreamDataEvent;
        const result = isEventInPir(streamEventMock);
        expect(result).toBeFalsy();
      });
    });

    describe('When data relationship type is not a relation in pir, but the rest is correct', () => {
      it('should return false', () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        const streamEventMock = {
          scope: 'internal',
          data: {
            relationship_type: 'random-relationship-type'
          }
        } as unknown as StreamDataEvent;
        const result = isEventInPir(streamEventMock);
        expect(result).toBeFalsy();
      });
    });

    describe('When isStixRelation is false, but the rest is correct', () => {
      it('should return false', () => {
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);
        const streamEventMock = {
          scope: 'internal',
          data: {
            relationship_type: RELATION_IN_PIR
          }
        } as unknown as StreamDataEvent;
        const result = isEventInPir(streamEventMock);
        expect(result).toBeFalsy();
      });
    });
  });
});
