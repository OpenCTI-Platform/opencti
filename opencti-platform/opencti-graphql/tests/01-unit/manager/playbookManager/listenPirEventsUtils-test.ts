import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildPirFilters,
  formatFiltersForPirPlaybookComponent,
  isEventInPirRelationshipMatchPir,
  isUpdateEventMatchPir,
  listenPirEvents,
  stixIdOfLinkedEntity
} from '../../../../src/manager/playbookManager/listenPirEventsUtils';
import type { SseEvent, StreamDataEvent } from '../../../../src/types/event';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import * as stixFiltering from '../../../../src/utils/filtering/filtering-stix/stix-filtering';
import * as middleware from '../../../../src/database/middleware';
import * as playbookExecutor from '../../../../src/manager/playbookManager/playbookExecutor';
import { RELATION_IN_PIR } from '../../../../src/schema/internalRelationship';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { PirStreamConfiguration } from '../../../../src/modules/playbook/components/data-stream-pir-component';
import { testContext } from '../../../utils/testQuery';

describe('listenPirEventsUtils', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });
  vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);

  type StixLoadReturn = Awaited<ReturnType<typeof middleware.stixLoadById>>;

  const mockEntity = {
    id: 'malware--id'
  } as unknown as StixLoadReturn;

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

  const secondPirList = [
    {
      label: 'test 3',
      value: 'pir-id-3',
      type: 'Pir'
    },
    {
      label: 'Test 4',
      value: 'pir-id-4',
      type: 'Pir'
    }
  ];

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
    playbook_definition: '{"nodes":[{"id":"id-14","name":"Listen PIR events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_DATA_STREAM_PIR","configuration":"{\\"inPirFilters\\":[{\\"label\\":\\"test patch\\",\\"value\\":\\"pir-id-1\\",\\"type\\":\\"Pir\\"}],\\"create\\":true,\\"delete\\":true,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[{\\\\\\"key\\\\\\":[\\\\\\"entity_type\\\\\\"],\\\\\\"operator\\\\\\":\\\\\\"eq\\\\\\",\\\\\\"values\\\\\\":[\\\\\\"Malware\\\\\\"],\\\\\\"mode\\\\\\":\\\\\\"or\\\\\\"}],\\\\\\"filterGroups\\\\\\":[]}\\"}"},{"id":"id-17","name":"Send to notifier","position":{"x":0,"y":300},"component_id":"PLAYBOOK_NOTIFIER_COMPONENT","configuration":"{\\"notifiers\\":[\\"id-18\\"],\\"authorized_members\\":[{\\"label\\":\\"admin@opencti.io\\",\\"value\\":\\"id-19\\",\\"type\\":\\"User\\"}]}"},{"id":"id-20","name":"Log data in standard output","position":{"x":0,"y":150},"component_id":"PLAYBOOK_LOGGER_COMPONENT","configuration":"{\\"level\\":\\"debug\\"}"}],"links":[{"id":"id-21","from":{"id":"id-20","port":"out"},"to":{"id":"id-17"}},{"id":"id-22","from":{"id":"id-14","port":"out"},"to":{"id":"id-20"}}]}',
    entity_type: 'Playbook',
    base_type: 'ENTITY',
    name: 'test pir',
    creator_id: ['id-19']
  } as unknown as BasicStoreEntityPlaybook;

  const randomNotMatchingPlaybook = {
    _id: 'id-15',
    id: 'id-15',
    playbook_definition: '{"nodes":[{"id":"id-14","name":"Listen PIR events","position":{"x":0,"y":0},"component_id":"PLAYBOOK_DATA_STREAM_PIR","configuration":"{\\"inPirFilters\\":[{\\"label\\":\\"test patch\\",\\"value\\":\\"pir-id-not-matching\\",\\"type\\":\\"Pir\\"}],\\"create\\":true,\\"delete\\":true,\\"filters\\":\\"{\\\\\\"mode\\\\\\":\\\\\\"and\\\\\\",\\\\\\"filters\\\\\\":[{\\\\\\"key\\\\\\":[\\\\\\"entity_type\\\\\\"],\\\\\\"operator\\\\\\":\\\\\\"eq\\\\\\",\\\\\\"values\\\\\\":[\\\\\\"Malware\\\\\\"],\\\\\\"mode\\\\\\":\\\\\\"or\\\\\\"}],\\\\\\"filterGroups\\\\\\":[]}\\"}"},{"id":"id-17","name":"Send to notifier","position":{"x":0,"y":300},"component_id":"PLAYBOOK_NOTIFIER_COMPONENT","configuration":"{\\"notifiers\\":[\\"id-18\\"],\\"authorized_members\\":[{\\"label\\":\\"admin@opencti.io\\",\\"value\\":\\"id-19\\",\\"type\\":\\"User\\"}]}"},{"id":"id-20","name":"Log data in standard output","position":{"x":0,"y":150},"component_id":"PLAYBOOK_LOGGER_COMPONENT","configuration":"{\\"level\\":\\"debug\\"}"}],"links":[{"id":"id-21","from":{"id":"id-20","port":"out"},"to":{"id":"id-17"}},{"id":"id-22","from":{"id":"id-14","port":"out"},"to":{"id":"id-20"}}]}',
    entity_type: 'Playbook',
    base_type: 'ENTITY',
    name: 'test pir',
    creator_id: ['id-19']
  } as unknown as BasicStoreEntityPlaybook;

  const eventDeleteInPirRelationship = {
    type: "delete",
    scope: "internal",
    message: "Malware `bloop 3` removed from Pir `FRASPA`",
    data: {
        id: "internal-relationship--43f00b41-5be2-4a2a-a3c1-c70edce5f090",
        type: "internal-relationship",
        extensions: {
            [STIX_EXT_OCTI]: {
                id: "5bebd777-05ac-47ae-85d9-007fe630d5b6",
                type: RELATION_IN_PIR,
                source_ref: "f29586c0-da5f-4305-bed2-94776df5a30c",
                source_ref_pir_refs: ["164ba8ba-f80a-4f10-8351-6a2931c790b1"],
                target_ref: "pir-id-1",
                target_type: "Pir",
                pir_score: 33,
                pir_explanation: [
                    {
                        dependencies: [{ "element_id": "948661f2-3c88-4d82-8987-c9585fe8e22e" }],
                        criterion: {
                            weight: 1,
                            filters: "{\"mode\":\"and\",\"filters\":[{\"key\":[\"entity_type\"],\"values\":[\"targets\"],\"operator\":\"eq\",\"mode\":\"or\"},{\"key\":[\"toId\"],\"values\":[\"a531156c-0a5e-4669-b284-ecf7cd0755c1\"],\"operator\":\"eq\",\"mode\":\"or\"}],\"filterGroups\":[]}"
                        }
                    }
                ]
            }
        },
        relationship_type: RELATION_IN_PIR,
        source_ref: "malware--44c11f09-53da-5ebf-ad44-38aec51d102e",
        target_ref: "pir--3eced404-1cbe-5c01-91af-68a0b08abbe6"
    }
} as unknown as StreamDataEvent;

const eventCreateInPirRelationship = {
    type: "create",
    scope: "internal",
    message: "Malware `bloop 2` added to Pir `FRASPA`",
    data: {
        id: "internal-relationship--4950216f-1041-49e0-8350-f665d61462f2",
        type: "internal-relationship",
        extensions: {
            [STIX_EXT_OCTI]: {
                id: "b9b1a3d4-1f6d-48c3-9ac4-f68571615ed0",
                type: RELATION_IN_PIR,
                source_ref: "70677291-d118-48e2-8f3b-ccfa55b7d565",
                source_type: "Malware",
                target_ref: "pir-id-1",
                target_type: "Pir",
                pir_score: 33,
                pir_explanation: [
                    {
                        dependencies: [{ "element_id": "97c29867-dce7-4fbf-9b7f-2020d3918e6e" }],
                        criterion: {
                            weight: 1,
                            filters: "{\"mode\":\"and\",\"filters\":[{\"key\":[\"entity_type\"],\"values\":[\"targets\"],\"operator\":\"eq\",\"mode\":\"or\"},{\"key\":[\"toId\"],\"values\":[\"a531156c-0a5e-4669-b284-ecf7cd0755c1\"],\"operator\":\"eq\",\"mode\":\"or\"}],\"filterGroups\":[]}"
                        }
                    }
                ]
            }
        },
        relationship_type: RELATION_IN_PIR,
        source_ref: "malware--6ee16aef-83ae-5c53-9718-9fed090f0dff",
        target_ref: "pir--3eced404-1cbe-5c01-91af-68a0b08abbe6"
    }
} as unknown as StreamDataEvent;

const eventCreateRelationshipWithNoPir = {
          type: "create",
          scope: "external",
          message: "creates the relation targets from `bloop 2` (Malware) to `France` (Country)",
          data: {
              id: "relationship--10e09cca-dcc7-5708-80fc-f4e7c4ca53be",
              type: "relationship",
              extensions: {
                  [STIX_EXT_OCTI]: {
                      id: "5ae4d075-f2df-48d0-823f-616621ea5c7c",
                      type: "targets",
                      source_ref: "70677291-d118-48e2-8f3b-ccfa55b7d565",
                      target_ref: "a531156c-0a5e-4669-b284-ecf7cd0755c1",
                  }
              },
              relationship_type: "targets",
              source_ref: "malware--6ee16aef-83ae-5c53-9718-9fed090f0dff",
              target_ref: "location--b8d0549f-de06-5ebd-a6e9-d31a581dba5d"
          }
      } as unknown as StreamDataEvent;

const eventDeleteRelationshipWithNoPir = {
          type: "delete",
          scope: "external",
          message: "Deletes the relation targets from `bloop 2` (Malware) to `France` (Country)",
          data: {
              id: "relationship--10e09cca-dcc7-5708-80fc-f4e7c4ca53be",
              type: "relationship",
              extensions: {
                  [STIX_EXT_OCTI]: {
                      id: "5ae4d075-f2df-48d0-823f-616621ea5c7c",
                      type: "targets",
                      source_ref: "70677291-d118-48e2-8f3b-ccfa55b7d565",
                      target_ref: "a531156c-0a5e-4669-b284-ecf7cd0755c1",
                  }
              },
              relationship_type: "targets",
              source_ref: "malware--6ee16aef-83ae-5c53-9718-9fed090f0dff",
              target_ref: "location--b8d0549f-de06-5ebd-a6e9-d31a581dba5d"
          }
      } as unknown as StreamDataEvent;

const eventUpdateEntityWithPir = {
    type: "update",
    scope: "external",
    message: "replaces `coucou 2` with `updated description` in `Description`",
    data: {
        id: "malware--6ee16aef-83ae-5c53-9718-9fed090f0dff",
        type: "malware",
        extensions: {
            [STIX_EXT_OCTI]: {
                id: "70677291-d118-48e2-8f3b-ccfa55b7d565",
                type: "Malware",
                pir_information: [
                    {
                        last_pir_score_date: "2025-12-01T09:08:44.783Z",
                        pir_id: "pir-id-1",
                        pir_score: 33
                    }
                ]
            }
        },
        name: "bloop 2",
        description: "updated description"
    },
    context: {
        patch: [
            {
                op: "replace",
                path: "/description",
                value: "updated description"
            },
        ],
        "reverse_patch": [
            {
                op: "replace",
                path: "/description",
                value: "coucou 2"
            },
        ],
        pir_ids: []
    } 
} as unknown as StreamDataEvent;

const eventCreateRelationshipWithOnlyFlaggedSource = {
    type: "create",
    scope: "external",
    message: "creates the relation exploits from `bloop 2` (Malware) to `CVE-2009-4324` (Vulnerability)",
    data: {
        id: "relationship--98ea260c-ad48-5433-b509-2f09d0eb3ffa",
        type: "relationship",
        extensions: {
            [STIX_EXT_OCTI]: {
                id: "a12785d6-450f-4a08-9741-31c48b627b17",
                type: "exploits",
                source_ref: "70677291-d118-48e2-8f3b-ccfa55b7d565",
                source_type: "Malware",
                source_ref_pir_refs: ["pir-id-1"],
                target_ref: "03695b51-8cad-429c-8f57-7860b73162c7",
                target_type: "Vulnerability"
            }
        },
        relationship_type: "exploits",
        source_ref: "malware--6ee16aef-83ae-5c53-9718-9fed090f0dff",
        target_ref: "vulnerability--target-id"
    }
} as unknown as StreamDataEvent;

const eventCreateRelationshipWithOnlyFlaggedTarget = {
    type: "create",
    scope: "external",
    message: "creates the relation exploits from `bloop 2` (Malware) to `CVE-2009-4324` (Vulnerability)",
    data: {
        id: "relationship--98ea260c-ad48-5433-b509-2f09d0eb3ffa",
        type: "relationship",
        extensions: {
            [STIX_EXT_OCTI]: {
                id: "a12785d6-450f-4a08-9741-31c48b627b17",
                type: "exploits",
                source_ref: "70677291-d118-48e2-8f3b-ccfa55b7d565",
                source_type: "Malware",
                target_ref_pir_refs: ["pir-id-1"],
                target_ref: "03695b51-8cad-429c-8f57-7860b73162c7",
                target_type: "Vulnerability"
            }
        },
        relationship_type: "exploits",
        source_ref: "malware--source-id",
        target_ref: "vulnerability--target-id"
    }
} as unknown as StreamDataEvent;

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
        testContext,
        eventDeleteInPirRelationship,
        { create: true } as PirStreamConfiguration,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
    });

    it('should return true when called with an event in Pir relationship, and a PIR list that match filters', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);

      const result = await isEventInPirRelationshipMatchPir(
        testContext,
        eventCreateInPirRelationship,
        { create: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeTruthy();
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
    });

    it('should return false when called with an event in Pir relationship, and PIR list that does not match filters', async () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = await isEventInPirRelationshipMatchPir(
        testContext,
        eventDeleteInPirRelationship,
        { create: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeFalsy();
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
    });
  });

  describe('isUpdateEventMatchPir', () => {
    it('should return true when called with update event, no PIR list and flagged entity', () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = isUpdateEventMatchPir(
        eventUpdateEntityWithPir,
        { update: true } as PirStreamConfiguration,
      );
      expect(result).toBe(true);
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
    });

    it('should return true when called with an event update on an entity, and is in a PIR that matches filters', () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      
      const result = isUpdateEventMatchPir(
        eventUpdateEntityWithPir,
        { update: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBe(true);
    });

    it('should return false when called with an event update on entity, and is in a PIR that does not match filters', () => {
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);

      const result = isUpdateEventMatchPir(
        eventUpdateEntityWithPir,
        { update: true } as PirStreamConfiguration,
        secondPirList,
      );
      expect(result).toBe(false);
    });

    it('should return false when event is not an update on a entity', () => {
      const result = isUpdateEventMatchPir(
        eventDeleteInPirRelationship,
        { update: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeFalsy();
    });
  });

  describe('stixIdOfLinkedEntity', () => {
    it('should return null if it is a stix relation with no PIR involved', () => {
      const result = stixIdOfLinkedEntity(
        eventCreateRelationshipWithNoPir,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeNull();
    });

    it('should return null if it is a stix relation but not a relationship creation', () => {
      const result = stixIdOfLinkedEntity(
        eventDeleteRelationshipWithNoPir,
        { create_rel: false } as PirStreamConfiguration,
        randomPirList,
      );
      expect(result).toBeNull();
    });

    it('should return expected id if there is no pirList and at least one source ref pir id', () => {
      const result = stixIdOfLinkedEntity(
        eventCreateRelationshipWithOnlyFlaggedSource,
        { create_rel: true } as PirStreamConfiguration,
      );
      expect(result).toBe('vulnerability--target-id');
    });

    it('should return expected id if there is no pirList and no source ref pir id, and target has at least one pir id', () => {

      const result = stixIdOfLinkedEntity(
        eventCreateRelationshipWithOnlyFlaggedTarget,
        { create_rel: true } as PirStreamConfiguration,
      );
      expect(result).toBe('malware--source-id');
    });

    it('should return expected id if there is a pirList that matches at least one of the source ref pir id', () => {

      const result = stixIdOfLinkedEntity(
        eventCreateRelationshipWithOnlyFlaggedSource,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList
      );
      expect(result).toBe('vulnerability--target-id');
    });

    it('should return expected id if there is a pirList that does not match the source ref pir id but matches at least one of the target ref pir id', () => {

      const result = stixIdOfLinkedEntity(
        eventCreateRelationshipWithOnlyFlaggedTarget,
        { create_rel: true } as PirStreamConfiguration,
        randomPirList
      );
      expect(result).toBe('malware--source-id');
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
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);
      vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);

      await listenPirEvents(
        testContext,
        {id: 'id-tested-event', data : {...eventDeleteInPirRelationship} } as unknown as SseEvent<StreamDataEvent>,
        randomInstance,
        randomPlaybook
      );
      expect(playbookExecutor.playbookExecutor).toHaveBeenCalledWith(expect.objectContaining({
        eventId: 'id-tested-event',
        executionId: expect.any(String),
        playbookId: randomPlaybook.id,
        dataInstanceId: expect.any(String),
        definition: expect.any(Object),
        previousStep: null,
        nextStep: expect.any(Object),
        previousStepBundle: null,
        bundle: expect.any(Object),
        event: eventDeleteInPirRelationship
      }));
    });

    it('should not call playbookExecutor when called with an event that is not in PIR but all the rest is good', async () => {
      vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(true);
      vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);

      await listenPirEvents(
        testContext,
        {id: 'id-tested-event', data : {...eventCreateRelationshipWithOnlyFlaggedSource} } as unknown as SseEvent<StreamDataEvent>,
        randomInstance,
        randomPlaybook
      );
      expect(stixFiltering.isStixMatchFilterGroup).not.toHaveBeenCalled();
      expect(middleware.stixLoadById).not.toHaveBeenCalled();
      expect(playbookExecutor.playbookExecutor).not.toHaveBeenCalled();
    });

    it('should not call playbookExecutor when called with an entity that does not match any filter', async () => {
      vi.spyOn(playbookExecutor, 'playbookExecutor').mockResolvedValue(undefined);
      vi.spyOn(stixFiltering, 'isStixMatchFilterGroup').mockResolvedValue(false);
      vi.spyOn(middleware, 'stixLoadById').mockResolvedValue(mockEntity);

      await listenPirEvents(
        testContext,
        {id: 'id-tested-event', data : {...eventDeleteInPirRelationship} } as unknown as SseEvent<StreamDataEvent>,
        randomInstance,
        randomNotMatchingPlaybook
      );
      expect(stixFiltering.isStixMatchFilterGroup).toHaveBeenCalled();
      expect(middleware.stixLoadById).not.toHaveBeenCalled();
      expect(playbookExecutor.playbookExecutor).not.toHaveBeenCalled();
    });
  });
});
