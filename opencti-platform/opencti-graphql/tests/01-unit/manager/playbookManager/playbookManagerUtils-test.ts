import { describe, expect, it, vi } from 'vitest';
import {
  isEventCreateRelationship,
  isEventInPirRelationship,
  isEventUpdateOnEntity,
  isValidEventType,
  StreamDataEventTypeEnum,
} from '../../../../src/manager/playbookManager/playbookManagerUtils';
import * as stixRelationship from '../../../../src/schema/stixRelationship';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import type { StreamDataEvent } from '../../../../src/types/event';

describe('playbookManagerUtils', () => {
  describe('isValidEventType', () => {
    it('should return true when evenType is correct and corresponding event in configuration is true', () => {
      const result = isValidEventType('create', { create: true });
      expect(result).toBeTruthy();
    });

    it('should return false when evenType is correct but corresponding event in configuration is false', () => {
      const result = isValidEventType('create', { create: false });
      expect(result).toBeFalsy();
    });
  });

  describe('isEventInPirRelationship', () => {
    it('should return true when scope is internal, data relationship type is relation in pir, and isStixRelation is true', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
      const streamEventMock = {
        scope: 'internal',
        data: {
          relationship_type: RELATION_IN_PIR,
        },
      } as unknown as StreamDataEvent;
      const result = isEventInPirRelationship(streamEventMock);
      expect(result).toBeTruthy();
    });

    it('should return false when scope is not internal, but the rest is correct', async () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
      const streamEventMock = {
        scope: 'external',
        data: {
          relationship_type: RELATION_IN_PIR,
        },
      } as unknown as StreamDataEvent;
      const result = await isEventInPirRelationship(streamEventMock);
      expect(result).toBeFalsy();
    });

    it('should return false when data relationship type is not a relation in pir, but the rest is correct', async () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
      const streamEventMock = {
        scope: 'internal',
        data: {
          relationship_type: 'random-relationship-type',
        },
      } as unknown as StreamDataEvent;
      const result = await isEventInPirRelationship(streamEventMock);
      expect(result).toBeFalsy();
    });

    it('should return false when isStixRelation is false, but the rest is correct', async () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);
      const streamEventMock = {
        scope: 'internal',
        data: {
          relationship_type: RELATION_IN_PIR,
        },
      } as unknown as StreamDataEvent;
      const result = await isEventInPirRelationship(streamEventMock);
      expect(result).toBeFalsy();
    });
  });

  describe('isEventUpdateOnEntity', () => {
    it('should return true when event type is update and data is not a stix relation', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);
      const streamEventMock = {
        type: 'update',
        data: {},
      } as unknown as StreamDataEvent;
      const result = isEventUpdateOnEntity(streamEventMock);
      expect(result).toBeTruthy();
    });

    it('should return false when event type is not update, but data is not a stix relation', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);
      const streamEventMock = {
        type: 'create',
        data: {},
      } as unknown as StreamDataEvent;
      const result = isEventUpdateOnEntity(streamEventMock);
      expect(result).toBeFalsy();
    });

    it('should return false when data is a stix relation, but event type is update', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
      const streamEventMock = {
        type: 'update',
        data: {},
      } as unknown as StreamDataEvent;
      const result = isEventUpdateOnEntity(streamEventMock);
      expect(result).toBeFalsy();
    });
  });

  describe('isEventCreateRelationship', () => {
    it('should return true if event scope is external, if event data is a stix relationship, and if the type af the event is create', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const streamEventMock = {
        type: StreamDataEventTypeEnum.CREATE,
        scope: 'external',
      } as unknown as StreamDataEvent;

      const result = isEventCreateRelationship(streamEventMock);

      expect(result).toBe(true);
    });

    it('should return false if all conditions are not met: not a stix relationship', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);

      const streamEventMock = {
        type: StreamDataEventTypeEnum.CREATE,
        scope: 'external',
      } as unknown as StreamDataEvent;

      const result = isEventCreateRelationship(streamEventMock);

      expect(result).toBe(false);
    });

    it('should return false if all conditions are not met: not an external event', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const streamEventMock = {
        type: StreamDataEventTypeEnum.CREATE,
        scope: 'internal',
      } as unknown as StreamDataEvent;

      const result = isEventCreateRelationship(streamEventMock);

      expect(result).toBe(false);
    });

    it('should return false if all conditions are not met: not a create type event', () => {
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const streamEventMock = {
        type: StreamDataEventTypeEnum.DELETE,
        scope: 'external',
      } as unknown as StreamDataEvent;

      const result = isEventCreateRelationship(streamEventMock);

      expect(result).toBe(false);
    });
  });
});
