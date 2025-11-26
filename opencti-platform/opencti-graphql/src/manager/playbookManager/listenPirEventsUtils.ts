import { v4 as uuidv4 } from 'uuid';
import { stixLoadById } from '../../database/middleware';
import { FilterMode, type FilterGroup } from '../../generated/graphql';
import { PLAYBOOK_COMPONENTS } from '../../modules/playbook/playbook-components';
import type { BasicStoreEntityPlaybook, ComponentDefinition, NodeDefinition } from '../../modules/playbook/playbook-types';
import type { PirStreamConfiguration } from '../../modules/playbook/components/data-stream-pir-component';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { isStixRelation } from '../../schema/stixRelationship';
import type { SseEvent, StreamDataEvent } from '../../types/event';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import type { AuthContext } from '../../types/user';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { isEventInPirRelationship, isEventUpdateOnEntity, isValidEventType } from './playbookManagerUtils';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { playbookExecutor } from './playbookExecutor';
import { storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntity } from '../../types/store';
import { PIR_SCORE_FILTER } from '../../utils/filtering/filtering-constants';

/**
 * Build a filterGroup to filter on PIR IDs.
 * @param pirList List of PIR IDs we want to filter.
 */
export const buildPirFilters = (pirList: { value: string }[]) => {
  return {
    filterGroups: [],
    mode: FilterMode.And,
    filters: [{
      key: ['toId'],
      values: pirList.map((n) => n.value),
    }],
  };
};

/**
 * Get the IDs of PIR an entity is flagged.
 * @param context To query DB.
 * @param entityId ID of the entity to retrieve flagged PIR.
 */
export const listOfPirInEntity = async (context: AuthContext, entityId: string) => {
  const entityFromId = await storeLoadById<BasicStoreEntity>(
    context,
    AUTOMATION_MANAGER_USER,
    entityId,
    ABSTRACT_STIX_CORE_OBJECT
  );
  return entityFromId.pir_information?.map((pir) => pir.pir_id) || [];
};

/**
 * Determine if an event matches the PIR configuration of the playbook.
 * It should either be:
 * - event on a relation in-pir concerning one of selected PIR,
 * - event update of an entity flagged by one of selected PIR.
 *
 * @param context To query DB.
 * @param eventData The event.
 * @param pirList List of selected PIR.
 * @returns True if the event matches selected PIR.
 */
export const isEventMatchesPir = async (
  context: AuthContext,
  eventData: StreamDataEvent,
  pirList?: { value: string }[]
) => {
  // If it's an event on relationship in-pir, we apply a filter of PIR ids directly on event.
  if (isEventInPirRelationship(eventData)) {
    // If entity is flagged and no PIR filtering set, it matches.
    if (!pirList || pirList.length === 0) return true;

    const filtersOnInPirRel = buildPirFilters(pirList);
    return isStixMatchFilterGroup(
      context,
      AUTOMATION_MANAGER_USER,
      eventData.data,
      filtersOnInPirRel
    );
  }

  // Else if it's an update of an entity, we check if this entity is flagged in PIR.
  if (isEventUpdateOnEntity(eventData)) {
    const entityPirList = await listOfPirInEntity(context, eventData.data.id);
    if (entityPirList.length > 0) {
      // If entity is flagged and no PIR filtering set, it matches.
      if (!pirList || pirList.length === 0) return true;
      // Otherwise check the entity is flagged in the corresponding PIR.
      return entityPirList.some((pirId) => pirList.some((selectedPir) => pirId === selectedPir.value));
    }
  }

  // By default, does not match.
  return false;
};

export const formatFiltersForPirPlaybookComponent = (sourceFilters: string, inPirFilters?: { value: string; }[]) => {
  const filtersOnSource: FilterGroup | undefined = sourceFilters ? JSON.parse(sourceFilters) : undefined;
  if (!filtersOnSource) return undefined;

  const formattedFirstLevelFilters = filtersOnSource.filters.map((filter) => {
    if (filter.key[0] === PIR_SCORE_FILTER) {
      return {
        key: [PIR_SCORE_FILTER],
        values: [
          { ...filter, key: 'score' },
          { key: 'pir_ids', values: (inPirFilters ?? []).map((pir) => pir.value) }
        ]
      };
    }
    return filter;
  });

  return { ...filtersOnSource, filters: formattedFirstLevelFilters };
};

export const listenPirEvents = async (
  context: AuthContext,
  streamEvent : SseEvent<StreamDataEvent>,
  instance: NodeDefinition,
  playbook: BasicStoreEntityPlaybook
) => {
  const { id: eventId, data: { data, type } } = streamEvent;
  const configuration = JSON.parse(instance.configuration ?? '{}') as PirStreamConfiguration;
  const { filters: sourceFilters, inPirFilters } = configuration;
  const filtersOnSource = formatFiltersForPirPlaybookComponent(sourceFilters, inPirFilters);

  if (isValidEventType(type, configuration)) {
    if (await isEventMatchesPir(context, streamEvent.data, inPirFilters)) {
      let isEntityMatchFilters: boolean = false;
      let stixEntity: StixObject | undefined;

      if (isEventInPirRelationship(streamEvent.data) && isStixRelation(data)) {
        stixEntity = await stixLoadById(context, AUTOMATION_MANAGER_USER, data.source_ref, ABSTRACT_STIX_CORE_OBJECT) as unknown as StixObject;
        isEntityMatchFilters = !!stixEntity && await isStixMatchFilterGroup(context, AUTOMATION_MANAGER_USER, stixEntity, filtersOnSource);
      } else if (isEventUpdateOnEntity(streamEvent.data)) {
        stixEntity = data;
        isEntityMatchFilters = await isStixMatchFilterGroup(context, AUTOMATION_MANAGER_USER, data, filtersOnSource);
      }

      if (isEntityMatchFilters && stixEntity) {
        const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
        const connector = PLAYBOOK_COMPONENTS[instance.component_id];
        const nextStep = { component: connector, instance };
        const bundle: StixBundle = {
          id: uuidv4(),
          spec_version: STIX_SPEC_VERSION,
          type: 'bundle',
          objects: [stixEntity]
        };
        await playbookExecutor({
          eventId,
          // Basic
          executionId: uuidv4(),
          playbookId: playbook.id,
          dataInstanceId: stixEntity.id,
          definition: def,
          // Steps
          previousStep: null,
          nextStep,
          // Data
          previousStepBundle: null,
          bundle,
          event: streamEvent.data
        });
      }
    }
  }
};
