import { v4 as uuidv4 } from 'uuid';
import { stixLoadById } from '../../database/middleware';
import { FilterMode, type FilterGroup } from '../../generated/graphql';
import { PLAYBOOK_COMPONENTS } from '../../modules/playbook/playbook-components';
import type { BasicStoreEntityPlaybook, ComponentDefinition, NodeDefinition } from '../../modules/playbook/playbook-types';
import type { PirStreamConfiguration } from '../../modules/playbook/components/data-stream-pir-component';
import { isStixRelation } from '../../schema/stixRelationship';
import type { SseEvent, StreamDataEvent } from '../../types/event';
import type { StixBundle, StixCoreObject, StixObject } from '../../types/stix-2-1-common';
import type { AuthContext } from '../../types/user';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { isEventCreateRelationship, isEventInPirRelationship, isEventUpdateOnEntity, isValidEventType } from './playbookManagerUtils';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { playbookExecutor } from './playbookExecutor';
import { PIR_SCORE_FILTER } from '../../utils/filtering/filtering-constants';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

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
export const getEntityPirIds = (entity: StixCoreObject) => {
  const { pir_information } = entity.extensions[STIX_EXT_OCTI];
  return pir_information?.map((pir) => pir.pir_id) || [];
};

/**
 * It should true if event on a relation in-pir is concerning one of selected PIR
 *
 * @param context To query DB.
 * @param eventData The event.
 * @param pirList List of selected PIR.
 * @returns True if the event matches selected PIR.
 */
export const isEventInPirRelationshipMatchPir = async (
  context: AuthContext,
  eventData: StreamDataEvent,
  config: PirStreamConfiguration,
  pirList?: { value: string }[],
) => {
  if (isEventInPirRelationship(eventData) && (config.create || config.delete)) {
    // If entity is flagged and no PIR filtering set, it matches.
    if (!pirList || pirList.length === 0) return true;

    const filtersOnInPirRel = buildPirFilters(pirList);
    return isStixMatchFilterGroup(
      context,
      AUTOMATION_MANAGER_USER,
      eventData.data,
      filtersOnInPirRel,
    );
  }
  // By default, does not match.
  return false;
};

/**
 * It should return true if the event update of an entity flagged by one of selected PIR.
 *
 * @param context To query DB.
 * @param eventData The event.
 * @param pirList List of selected PIR.
 * @returns True if the event matches selected PIR.
 */
export const isUpdateEventMatchPir = (
  eventData: StreamDataEvent,
  config: PirStreamConfiguration,
  pirList?: { value: string }[],
) => {
  if (isEventUpdateOnEntity(eventData) && config.update) {
    const entityPirList = getEntityPirIds(eventData.data);
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

/**
 * It should return the id of the entity linked to an entity flagged by one of selected PIR.
 *
 * @param eventData The event.
 * @param pirList List of selected PIR.
 * @returns the id of the linked entity if the event matches selected PIR.
 */
export const stixIdOfLinkedEntity = (
  eventData: StreamDataEvent,
  config: PirStreamConfiguration,
  pirList?: { value: string }[],
) => {
  if (isEventCreateRelationship(eventData) && isStixRelation(eventData.data) && config.create_rel) {
    const { source_ref_pir_refs, target_ref_pir_refs } = eventData.data.extensions[STIX_EXT_OCTI];
    // In case no PIR is selected, it means any PIR.
    if (!pirList || pirList.length === 0) {
      if (source_ref_pir_refs && source_ref_pir_refs.length > 0) {
        return eventData.data.target_ref;
      }
      if (target_ref_pir_refs && target_ref_pir_refs.length > 0) {
        return eventData.data.source_ref;
      }
    } else if (source_ref_pir_refs && pirList.some((pirId) => source_ref_pir_refs.includes(pirId.value))) {
      return eventData.data.target_ref;
    } else if (target_ref_pir_refs && pirList.some((pirId) => target_ref_pir_refs.includes(pirId.value))) {
      return eventData.data.source_ref;
    }
  }
  return null;
};

export const formatFiltersForPirPlaybookComponent = (sourceFilters: string, inPirFilters?: { value: string }[]) => {
  const filtersOnSource: FilterGroup | undefined = sourceFilters ? JSON.parse(sourceFilters) : undefined;
  if (!filtersOnSource) return undefined;

  const formattedFirstLevelFilters = filtersOnSource.filters.map((filter) => {
    if (filter.key[0] === PIR_SCORE_FILTER) {
      return {
        key: [PIR_SCORE_FILTER],
        values: [
          { ...filter, key: 'score' },
          { key: 'pir_ids', values: (inPirFilters ?? []).map((pir) => pir.value) },
        ],
      };
    }
    return filter;
  });

  return { ...filtersOnSource, filters: formattedFirstLevelFilters };
};

export const listenPirEvents = async (
  context: AuthContext,
  streamEvent: SseEvent<StreamDataEvent>,
  instance: NodeDefinition,
  playbook: BasicStoreEntityPlaybook,
) => {
  const { id: eventId, data: { data, type } } = streamEvent;
  const configuration = JSON.parse(instance.configuration ?? '{}') as PirStreamConfiguration;
  const { filters: sourceFilters, inPirFilters } = configuration;
  const filtersOnSource = formatFiltersForPirPlaybookComponent(sourceFilters, inPirFilters);

  // Check that event type matches the active toggles of the config.
  if (isValidEventType(type, configuration)) {
    let stixEntity: StixObject | undefined;
    const isInPirRel = await isEventInPirRelationshipMatchPir(context, streamEvent.data, configuration, inPirFilters);
    const isUpdateEvent = isUpdateEventMatchPir(streamEvent.data, configuration, inPirFilters);
    const stixIdLinked = stixIdOfLinkedEntity(streamEvent.data, configuration, inPirFilters);

    if (isInPirRel && isStixRelation(data)) {
      // Event on relationship in-pir.
      stixEntity = await stixLoadById(
        context,
        AUTOMATION_MANAGER_USER,
        data.source_ref,
      ) as StixObject;
    } else if (isUpdateEvent) {
      // Event update on flagged entity.
      stixEntity = data;
    } else if (stixIdLinked) {
      // Event create relationship.
      stixEntity = await stixLoadById(
        context,
        AUTOMATION_MANAGER_USER,
        stixIdLinked,
      ) as StixObject;
    }

    // Having an entity means we have a matched PIR.
    if (stixEntity) {
      const isEntityMatchesFilters = await isStixMatchFilterGroup(context, AUTOMATION_MANAGER_USER, stixEntity, filtersOnSource);
      // Check if the entity of interest matches other filters.
      if (isEntityMatchesFilters) {
        const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
        const connector = PLAYBOOK_COMPONENTS[instance.component_id];
        const nextStep = { component: connector, instance };
        const bundle: StixBundle = {
          id: uuidv4(),
          spec_version: STIX_SPEC_VERSION,
          type: 'bundle',
          objects: [stixEntity],
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
          event: streamEvent.data,
        });
      }
    }
  }
};
