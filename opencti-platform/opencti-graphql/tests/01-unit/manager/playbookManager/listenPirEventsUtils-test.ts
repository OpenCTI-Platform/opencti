import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildPirFilters, isEventMatchesPir, listenPirEvents } from '../../../../src/manager/playbookManager/listenPirEventsUtils';
import type { AuthContext } from '../../../../src/types/user';
import type { SseEvent, StreamDataEvent } from '../../../../src/types/event';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import * as playbookUtils from '../../../../src/manager/playbookManager/playbookManagerUtils';
import * as stixRelationship from '../../../../src/schema/stixRelationship';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as middleware from '../../../../src/database/middleware';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as playbookExecutor from '../../../../src/manager/playbookManager/playbookExecutor';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';

describe('listenPirEventsUtils', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  type StixLoadReturn = Awaited<ReturnType<typeof middleware.stixLoadById>>;

  const mockEntity = {
    id: 'malware--id'
  } as unknown as StixLoadReturn;

  vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);

  const randomContext = {
    source: 'playbook_manager'
  } as unknown as AuthContext;

  const randomPirList = [
    {
      label: 'test 1',
      value: 'id-1',
      type: 'Pir'
    },
    {
      label: 'Test 2',
      value: 'id-2',
      type: 'Pir'
    }
  ];

  const randomEventInPir = {
    id: 'event-id-123',
    data: {
      id: 'internal-relationship--id-3',
      scope: 'internal',
      type: 'create',
      data: { relationship_type: RELATION_IN_PIR, },
      extensions: { 'extension-definition--id-4':
        {
          id: 'id-5',
          type: 'in-pir',
          source_ref_pir_refs: ['id-1'],
          target_ref: 'id-1'
        } },
    } } as unknown as SseEvent<StreamDataEvent>;

  const randomEventNotInPir = { ...randomEventInPir, data: { ...randomEventInPir.data, data: { relationship_type: 'not-pir-relationship' }, } } as unknown as SseEvent<StreamDataEvent>;

  const randomUpdateEventOnEntity = { data: {
    type: 'update',
    scope: 'external',
    data: {
      id: 'malware--id',
    }
  } } as unknown as SseEvent<StreamDataEvent>;

  const randomInstance = {
    id: 'id-14',
    name: 'Listen PIR events',
    position: { x: 0, y: 0 },
    component_id: 'PLAYBOOK_DATA_STREAM_PIR',
    configuration: '{"inPirFilters":[{"label":"test patch","value":"id-1","type":"Pir"}],"create":true,"delete":true,"filters":"{\\"mode\\":\\"and\\",\\"filters\\":[{\\"key\\":[\\"entity_type\\"],\\"operator\\":\\"eq\\",\\"values\\":[\\"Malware\\"],\\"mode\\":\\"or\\"}],\\"filterGroups\\":[]}"}'
  };

  const randomPlaybook = {
    _id: 'id-15',
    id: 'id-15',
    playbook_definition: '{"nodes":[{"id":"id-14","name":"Listen PIR events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_DATA_STREAM_PIR","configuration":"{\\"inPirFilters\\":[{\\"label\\":\\"test patch\\",\\"value\\":\\"id-1\\",\\"type\\":\\"Pir\\"}],\\"create\\":true,\\"delete\\":true,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[{\\\\\\"key\\\\\\":[\\\\\\"entity_type\\\\\\"],\\\\\\"operator\\\\\\":\\\\\\"eq\\\\\\",\\\\\\"values\\\\\\":[\\\\\\"Malware\\\\\\"],\\\\\\"mode\\\\\\":\\\\\\"or\\\\\\"}],\\\\\\"filterGroups\\\\\\":[]}\\"}"},{"id":"id-17","name":"Send to notifier","position":{"x":0,"y":300},"component_id":"PLAYBOOK_NOTIFIER_COMPONENT","configuration":"{\\"notifiers\\":[\\"id-18\\"],\\"authorized_members\\":[{\\"label\\":\\"admin@opencti.io\\",\\"value\\":\\"id-19\\",\\"type\\":\\"User\\"}]}"},{"id":"id-20","name":"Log data in standard output","position":{"x":0,"y":150},"component_id":"PLAYBOOK_LOGGER_COMPONENT","configuration":"{\\"level\\":\\"debug\\"}"}],"links":[{"id":"id-21","from":{"id":"id-20","port":"out"},"to":{"id":"id-17"}},{"id":"id-22","from":{"id":"id-14","port":"out"},"to":{"id":"id-20"}}]}',
    entity_type: 'Playbook',
    base_type: 'ENTITY',
    name: 'test pir',
    creator_id: ['id-19']
  } as unknown as BasicStoreEntityPlaybook;

  describe('When buildPirFilters is called with a list of PIR', () => {
    const pirFilters = buildPirFilters(randomPirList);
    const expectedResult = {
      filterGroups: [],
      mode: 'and',
      filters: [{
        key: ['toId'],
        values: [
          'id-1',
          'id-2'
        ]
      }]
    };
    it('should return correct filters', () => {
      expect(pirFilters).toEqual(expectedResult);
    });
  });

  describe('When isEventMatchesPir is called with no PIR list', () => {
    it('should return true', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await isEventMatchesPir(
        randomContext,
        randomEventInPir.data,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
    });
  });

  describe('When isEventMatchesPir is called with an event in Pir relationship, and a PIR list that match filters', () => {
    it('should return true', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

      const result = await isEventMatchesPir(
        randomContext,
        randomEventInPir.data,
        randomPirList,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
    });
  });

  describe('When isEventMatchesPir is called with an event in Pir relationship, and PIR list that does not match filters', () => {
    it('should return false', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await isEventMatchesPir(
        randomContext,
        randomEventInPir.data,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
    });
  });

  describe('When isEventMatchesPir is called with an event update on entity, and is in a PIR that matches filters', () => {
    it('should return true', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({ pir_information: [{ pir_id: 'id-2' }] } as unknown as BasicStoreEntityPlaybook);

      const result = await isEventMatchesPir(
        randomContext,
        randomUpdateEventOnEntity.data,
        randomPirList,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
      expect(middlewareLoader.storeLoadById).toHaveBeenCalled();
    });
  });

  describe('When isEventMatchesPir is called with an event update on entity, and is in a PIR that does not match filters', () => {
    it('should return false', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({ pir_information: [{ pir_id: 'not good pir id' }] } as unknown as BasicStoreEntityPlaybook);

      const result = await isEventMatchesPir(
        randomContext,
        randomUpdateEventOnEntity.data,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
      expect(middlewareLoader.storeLoadById).toHaveBeenCalled();
    });
  });

  describe('When isEventMatchesPir is called with an event that is not a in pir relationship and not an update en entity', () => {
    it('should return false', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await isEventMatchesPir(
        randomContext,
        randomEventNotInPir.data,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
    });
  });

  describe('When listenPirEvents is called with event in PIR, stix data, valid event type, and matching PIR, and entity matches a filter', () => {
    it('should call playbookExecutor', async () => {
      vi.spyOn(playbookUtils, 'isValidEventType').mockReturnValue(true);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);
      vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);
      await listenPirEvents(
        randomContext,
        randomEventInPir,
        randomInstance,
        randomPlaybook
      );
      expect(playbookExecutor.playbookExecutor).toHaveBeenCalledWith(expect.objectContaining({
        eventId: randomEventInPir.id,
        executionId: expect.any(String),
        playbookId: randomPlaybook.id,
        dataInstanceId: expect.any(String),
        definition: expect.any(Object),
        previousStep: null,
        nextStep: expect.any(Object),
        previousStepBundle: null,
        bundle: expect.any(Object),
        event: randomEventInPir.data
      }));
    });

    describe('When listenPirEvents is called with an event that is not in PIR but all the rest is good', () => {
      it('should not call playbookExecutor', async () => {
        vi.spyOn(playbookUtils, 'isValidEventType').mockReturnValue(true);
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);
        vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);
        await listenPirEvents(
          randomContext,
          randomEventNotInPir,
          randomInstance,
          randomPlaybook
        );
        expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
        expect(playbookUtils.isValidEventType).toHaveBeenCalled();
        expect(middleware.stixLoadById).not.toHaveBeenCalled();
        expect(playbookExecutor.playbookExecutor).not.toHaveBeenCalled();
      });
    });

    describe('When listenPirEvents is called with a not valid event but all the rest is good', () => {
      it('should not call playbookExecutor', async () => {
        vi.spyOn(playbookUtils, 'isValidEventType').mockReturnValue(false);
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);
        vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);
        await listenPirEvents(
          randomContext,
          randomEventInPir,
          randomInstance,
          randomPlaybook
        );
        expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
        expect(middleware.stixLoadById).not.toHaveBeenCalled();
        expect(playbookExecutor.playbookExecutor).not.toHaveBeenCalled();
      });
    });

    describe('When listenPirEvents is called but the entity does not match any filter', () => {
      it('should not call playbookExecutor', async () => {
        vi.spyOn(playbookUtils, 'isValidEventType').mockReturnValue(true);
        vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);
        vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
        vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);
        await listenPirEvents(
          randomContext,
          randomEventInPir,
          randomInstance,
          randomPlaybook
        );
        expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
        expect(playbookUtils.isValidEventType).toHaveBeenCalled();
        expect(middleware.stixLoadById).not.toHaveBeenCalled();
        expect(playbookExecutor.playbookExecutor).not.toHaveBeenCalled();
      });
    });
  });
});
