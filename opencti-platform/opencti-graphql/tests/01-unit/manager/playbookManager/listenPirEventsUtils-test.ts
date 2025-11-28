import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildPirFilters,
  formatFiltersForPirPlaybookComponent,
  isEventInPirRelationshipMatchPir,
  isUpdateEventMatchPir,
  listenPirEvents,
  stixIdOfLinkedEntity
} from '../../../../src/manager/playbookManager/listenPirEventsUtils';
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
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { PirStreamConfiguration } from '../../../../src/modules/playbook/components/data-stream-pir-component';

describe('listenPirEventsUtils', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
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
      value: 'pir-id-1',
      type: 'Pir'
    },
    {
      label: 'Test 2',
      value: 'pir-id-2',
      type: 'Pir'
    }
  ];

  const randomEventInPir = {
    id: 'event-id-123',
    data: {
      id: 'internal-relationship--id-3',
      scope: 'internal',
      type: 'create',
      data: { relationship_type: RELATION_IN_PIR,
        extensions: { [STIX_EXT_OCTI]:
        {
          id: 'id-5',
          type: 'in-pir',
          source_ref_pir_refs: ['pir-id-1'],
          target_ref: 'id-1'
        } },
        target_ref: 'target-id'
      },

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

  describe('buildPirFilters', () => {
    const pirFilters = buildPirFilters(randomPirList);
    const expectedResult = {
      filterGroups: [],
      mode: 'and',
      filters: [{
        key: ['toId'],
        values: [
          'pir-id-1',
          'pir-id-2'
        ]
      }]
    };
    it('should return correct filters when called with a list of PIR', () => {
      expect(pirFilters).toEqual(expectedResult);
    });
  });

  describe('isEventInPirRelationshipMatchPir', () => {
    it('should return true when called with no PIR list', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await isEventInPirRelationshipMatchPir(
        randomContext,
        randomEventInPir.data,
        { create: true } as PirStreamConfiguration,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
    });

    it('should return true when called with an event in Pir relationship, and a PIR list that match filters', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

      const result = await isEventInPirRelationshipMatchPir(
        randomContext,
        randomEventInPir.data,
        { create: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
    });

    it('should return false when called with an event in Pir relationship, and PIR list that does not match filters', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await isEventInPirRelationshipMatchPir(
        randomContext,
        randomEventInPir.data,
        { create: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
    });
  });

  describe('isUpdateEventMatchPir', () => {
    it('should return true when called with no PIR list and flagged entity', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      vi.spyOn(playbookUtils, 'isEventUpdateOnEntity').mockResolvedValue(true);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({ pir_information: [{ pir_id: 'id-2' }] } as unknown as BasicStoreEntityPlaybook);

      const result = await isUpdateEventMatchPir(
        randomEventInPir.data,
        { update: true } as PirStreamConfiguration,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
    });

    it('should return true when called with an event update on an entity, and is in a PIR that matches filters', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({ pir_information: [{ pir_id: 'pir-id-2' }] } as unknown as BasicStoreEntityPlaybook);

      const result = await isUpdateEventMatchPir(
        randomUpdateEventOnEntity.data,
        { update: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeTruthy();
      expect(middlewareLoader.storeLoadById).toHaveBeenCalled();
    });

    it('should return false when called with an event update on entity, and is in a PIR that does not match filters', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({ pir_information: [{ pir_id: 'not good pir id' }] } as unknown as BasicStoreEntityPlaybook);
      const result = await isUpdateEventMatchPir(
        randomUpdateEventOnEntity.data,
        { update: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(middlewareLoader.storeLoadById).toHaveBeenCalled();
    });

    it('should return false when event is not an update on a entity', async () => {
      vi.spyOn(playbookUtils, 'isEventUpdateOnEntity').mockReturnValue(false);
      vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({} as unknown as BasicStoreEntityPlaybook);

      const result = await isUpdateEventMatchPir(
        randomUpdateEventOnEntity.data,
        { update: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(middlewareLoader.storeLoadById).not.toHaveBeenCalled();
    });
  });

  describe('stixIdOfLinkedEntity', () => {
    it('should return null if it is a stix relation but not a relationship creation', async () => {
      vi.spyOn(playbookUtils, 'isEventCreateRelationship').mockReturnValue(false);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const result = await stixIdOfLinkedEntity(
        randomEventInPir.data,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeNull();
    });

    it('should return null if it is a relationship creation but not a stix relationship', async () => {
      vi.spyOn(playbookUtils, 'isEventCreateRelationship').mockReturnValue(true);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(false);

      const result = await stixIdOfLinkedEntity(
        randomEventInPir.data,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeNull();
    });

    it('should return expected id if there is no pirList and at least one source ref pir id', async () => {
      vi.spyOn(playbookUtils, 'isEventCreateRelationship').mockReturnValue(true);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const randomEventInPirWithPirOnlyInSource = { ...randomEventInPir };

      const result = await stixIdOfLinkedEntity(
        randomEventInPirWithPirOnlyInSource.data,
        { create_rel: true } as PirStreamConfiguration,
      );
      expect(result).toBe('target-id');
    });

    it('should return expected id if there is no pirList and no source ref pir id, and target has at least one pir id', async () => {
      vi.spyOn(playbookUtils, 'isEventCreateRelationship').mockReturnValue(true);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const randomEventInPirWithPirOnlyInTarget = {
        ...randomEventInPir,
        data: { ...randomEventInPir.data,
          data: { ...randomEventInPir.data.data,
            extensions: {
              [STIX_EXT_OCTI]: {
                id: 'id-5',
                type: 'in-pir',
                source_ref_pir_refs: [],
                target_ref_pir_refs: ['id-345'],
                target_ref: 'id-1'
              } },
            source_ref: 'source-id'
          }
        }
      } as unknown as SseEvent<StreamDataEvent>;

      const result = await stixIdOfLinkedEntity(
        randomEventInPirWithPirOnlyInTarget.data,
        { create_rel: true } as PirStreamConfiguration,
      );
      expect(result).toBe('source-id');
    });

    it('should return expected id if there is a pirList that matches at least one of the source ref pir id', async () => {
      vi.spyOn(playbookUtils, 'isEventCreateRelationship').mockReturnValue(true);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const randomEventInPirWithMatchingPirInSource = { ...randomEventInPir };

      const result = await stixIdOfLinkedEntity(
        randomEventInPirWithMatchingPirInSource.data,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList
      );
      expect(result).toBe('target-id');
    });

    it('should return expected id if there is a pirList that does not match the source ref pir id but matches at least one of the target ref pir id', async () => {
      vi.spyOn(playbookUtils, 'isEventCreateRelationship').mockReturnValue(true);
      vi.spyOn(stixRelationship, 'isStixRelation').mockReturnValue(true);

      const randomEventInPirWithMatchingPirInTarget = {
        ...randomEventInPir,
        data: { ...randomEventInPir.data,
          data: { ...randomEventInPir.data.data,
            extensions: {
              [STIX_EXT_OCTI]: {
                id: 'id-5',
                type: 'in-pir',
                source_ref_pir_refs: ['id-345'],
                target_ref_pir_refs: ['pir-id-2'],
                target_ref: 'id-1'
              } },
            source_ref: 'source-id',
            target_ref: 'target-ref'
          }
        }
      } as unknown as SseEvent<StreamDataEvent>;

      const result = await stixIdOfLinkedEntity(
        randomEventInPirWithMatchingPirInTarget.data,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList
      );
      expect(result).toBe('source-id');
    });
  });

  describe('formatFilters', () => {
    it('should format filters correctly', () => {
      const sourceFilters = JSON.stringify({
        mode: 'and',
        filters: [
          {
            key: ['entity_type'],
            operator: 'eq',
            values: ['Malware'],
          },
          {
            key: ['pir_score'],
            operator: 'gte',
            values: [70],
          }
        ],
      });

      const inPirFilters = [
        { label: 'PIR 1', value: 'pir--id-1', type: 'Pir' },
        { label: 'PIR 2', value: 'pir--id-2', type: 'Pir' }
      ];

      const formattedFilters = formatFiltersForPirPlaybookComponent(sourceFilters, inPirFilters);
      const expectedFilters = {
        mode: 'and',
        filters: [
          {
            key: ['entity_type'],
            operator: 'eq',
            values: ['Malware'],
          },
          {
            key: ['pir_score'],
            values: [
              {
                key: 'score',
                operator: 'gte',
                values: [70],
              },
              {
                key: 'pir_ids',
                values: ['pir--id-1', 'pir--id-2']
              }
            ]
          }
        ],
      };

      expect(formattedFilters).toEqual(expectedFilters);
    });
  });

  describe('listenPirEvents', () => {
    it('should call playbookExecutor when called with event in PIR, stix data, valid event type, and matching PIR, and entity matches a filter', async () => {
      vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);
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

    it('should not call playbookExecutor when called with an event that is not in PIR but all the rest is good', async () => {
      vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);
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

    it('should not call playbookExecutor when called with a not valid event but all the rest is good', async () => {
      vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);
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

    it('should not call playbookExecutor when called but the entity does not match any filter', async () => {
      vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);
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
