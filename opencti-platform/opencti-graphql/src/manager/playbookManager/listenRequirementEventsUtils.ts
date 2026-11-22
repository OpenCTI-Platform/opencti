import { v4 as uuidv4 } from 'uuid';
import * as jsonpatch from 'fast-json-patch';
import { stixLoadById } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import type { FilterGroup } from '../../generated/graphql';
import { PLAYBOOK_COMPONENTS } from '../../modules/playbook/playbook-components';
import type { BasicStoreEntityPlaybook, ComponentDefinition, NodeDefinition } from '../../modules/playbook/playbook-types';
import type { RequirementStreamConfiguration } from '../../modules/playbook/components/data-stream-requirement-component';
import {
  type BasicStoreEntityIntelligenceRequirementMatch,
  ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH,
  isInRequirement,
  type StixIntelligenceRequirementMatch,
} from '../../modules/intelligenceRequirement/intelligenceRequirementMatch-types';
import { isStixRelation } from '../../schema/stixRelationship';
import type { SseEvent, StreamDataEvent, UpdateEvent } from '../../types/event';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import type { AuthContext } from '../../types/user';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { isEventCreateRelationship, isEventUpdateOnEntity, isValidEventType, StreamDataEventTypeEnum } from './playbookManagerUtils';
import { playbookExecutor } from './playbookExecutor';

// Entry point "Listen intelligence requirement events" (PLAYBOOK_DATA_STREAM_INTELLIGENCE_REQUIREMENT), the successor of
// "Listen PIR events". Same four toggles, same output (a bundle holding the entity of interest):
// - create: an entity enters a selected requirement (its match is created part of it, or becomes part of it);
// - delete: an entity leaves a selected requirement (its match is deleted, or stops being part of it);
// - update: an entity part of a selected requirement is updated;
// - create_rel: an entity is linked to an entity part of a selected requirement (the other end is the entity of interest).
// The matches travel on the stream with the internal scope (INTERNAL_EXPORTABLE_TYPES), as in-pir does.

type RequirementSelection = { value: string }[] | undefined;

const selectedIds = (requirementFilters: RequirementSelection) => (requirementFilters ?? [])
  .map((r) => r?.value)
  .filter((id): id is string => typeof id === 'string' && id.length > 0);

const isSelected = (irId: string, requirementFilters: RequirementSelection) => {
  const ids = selectedIds(requirementFilters);
  return ids.length === 0 || ids.includes(irId);
};

export const isRequirementMatchEvent = (eventData: StreamDataEvent) => {
  const { data, scope } = eventData;
  return scope === 'internal' && data?.extensions?.[STIX_EXT_OCTI]?.type === ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH;
};

const matchIsIn = (match: Partial<StixIntelligenceRequirementMatch> | undefined) => !!match
  && typeof match.match_status === 'string'
  && isInRequirement({ match_status: match.match_status, match_excluded: match.match_excluded ?? false });

/**
 * The previous state of a match from an update event (its reverse patch applied), undefined when it cannot be rebuilt.
 */
export const previousMatchOfUpdate = (eventData: UpdateEvent): StixIntelligenceRequirementMatch | undefined => {
  const reversePatch = eventData.context?.reverse_patch;
  if (!Array.isArray(reversePatch)) return undefined;
  try {
    const { newDocument } = jsonpatch.applyPatch(structuredClone(eventData.data), reversePatch, false, false);
    return newDocument as unknown as StixIntelligenceRequirementMatch;
  } catch {
    return undefined;
  }
};

export type RequirementTransition = 'enter' | 'leave' | null;

/**
 * Entry or exit carried by an event on a match. Pure.
 * create of a match part of the requirement = enter; delete of a match that was part of it = leave;
 * update = enter or leave when "part of the requirement" changes (status accepted, rejected, removed, excluded).
 */
export const requirementTransitionOfMatchEvent = (eventData: StreamDataEvent): RequirementTransition => {
  if (!isRequirementMatchEvent(eventData)) return null;
  const match = eventData.data as unknown as StixIntelligenceRequirementMatch;
  if (eventData.type === StreamDataEventTypeEnum.CREATE) return matchIsIn(match) ? 'enter' : null;
  if (eventData.type === StreamDataEventTypeEnum.DELETE) return matchIsIn(match) ? 'leave' : null;
  if (eventData.type === StreamDataEventTypeEnum.UPDATE) {
    const previous = previousMatchOfUpdate(eventData as UpdateEvent);
    if (!previous) return null;
    const wasIn = matchIsIn(previous);
    const isIn = matchIsIn(match);
    if (!wasIn && isIn) return 'enter';
    if (wasIn && !isIn) return 'leave';
  }
  return null;
};

/**
 * The entity id (internal) a match event is about when its transition is one the configuration listens to and its
 * requirement is selected. Pure.
 */
export const entityIdOfMatchEvent = (eventData: StreamDataEvent, config: RequirementStreamConfiguration): string | null => {
  const transition = requirementTransitionOfMatchEvent(eventData);
  if (!transition) return null;
  if (transition === 'enter' && !config.create) return null;
  if (transition === 'leave' && !config.delete) return null;
  const match = eventData.data as unknown as StixIntelligenceRequirementMatch;
  if (!match.match_entity_id || !isSelected(match.ir_id, config.requirementFilters)) return null;
  return match.match_entity_id;
};

/**
 * The ids, among the given entities, that are part of one of the selected requirements (any requirement when none is
 * selected), read from the stored matches.
 */
export const entitiesInSelectedRequirements = async (context: AuthContext, entityIds: string[], requirementFilters: RequirementSelection) => {
  const ids = entityIds.filter((id) => typeof id === 'string' && id.length > 0);
  if (ids.length === 0) return new Set<string>();
  let filters = addFilter(undefined, 'match_entity_id', ids);
  const selected = selectedIds(requirementFilters);
  if (selected.length > 0) filters = addFilter(filters, 'ir_id', selected);
  const matches = await fullEntitiesList<BasicStoreEntityIntelligenceRequirementMatch>(
    context,
    AUTOMATION_MANAGER_USER,
    [ENTITY_TYPE_INTELLIGENCE_REQUIREMENT_MATCH],
    { filters },
  );
  return new Set(matches.filter(isInRequirement).map((m) => m.match_entity_id));
};

const parseSourceFilters = (sourceFilters: string | undefined): FilterGroup | undefined => {
  if (!sourceFilters) return undefined;
  try {
    return JSON.parse(sourceFilters) as FilterGroup;
  } catch {
    return undefined;
  }
};

/**
 * The entity of interest of an event for this configuration, or undefined when the event is not one it listens to.
 */
export const resolveRequirementEventEntity = async (
  context: AuthContext,
  eventData: StreamDataEvent,
  config: RequirementStreamConfiguration,
): Promise<StixObject | undefined> => {
  const { data } = eventData;
  // 1. An entity enters or leaves a requirement
  const matchEntityId = entityIdOfMatchEvent(eventData, config);
  if (matchEntityId) {
    return await stixLoadById(context, AUTOMATION_MANAGER_USER, matchEntityId) as StixObject | undefined;
  }
  if (isRequirementMatchEvent(eventData)) return undefined;
  // 2. An entity part of a requirement is updated
  if (config.update && isEventUpdateOnEntity(eventData)) {
    const entityId = data.extensions?.[STIX_EXT_OCTI]?.id;
    if (entityId) {
      const inRequirement = await entitiesInSelectedRequirements(context, [entityId], config.requirementFilters);
      if (inRequirement.has(entityId)) return data;
    }
    return undefined;
  }
  // 3. An entity is linked to an entity part of a requirement: the other end is the entity of interest
  if (config.create_rel && isEventCreateRelationship(eventData) && isStixRelation(data)) {
    const extension = data.extensions[STIX_EXT_OCTI];
    const sourceId = extension.source_ref;
    const targetId = extension.target_ref;
    const inRequirement = await entitiesInSelectedRequirements(context, [sourceId, targetId], config.requirementFilters);
    if (inRequirement.has(sourceId)) {
      return await stixLoadById(context, AUTOMATION_MANAGER_USER, data.target_ref) as StixObject | undefined;
    }
    if (inRequirement.has(targetId)) {
      return await stixLoadById(context, AUTOMATION_MANAGER_USER, data.source_ref) as StixObject | undefined;
    }
  }
  return undefined;
};

export const listenRequirementEvents = async (
  context: AuthContext,
  streamEvent: SseEvent<StreamDataEvent>,
  instance: NodeDefinition,
  playbook: BasicStoreEntityPlaybook,
) => {
  const { id: eventId, data: { type } } = streamEvent;
  const configuration = JSON.parse(instance.configuration ?? '{}') as RequirementStreamConfiguration;
  // An entry or an exit can come as an update of the match (status or exclusion changed): its own toggle decides
  if (!isRequirementMatchEvent(streamEvent.data) && !isValidEventType(type, configuration)) return;
  const stixEntity = await resolveRequirementEventEntity(context, streamEvent.data, configuration);
  if (!stixEntity) return;
  const filtersOnSource = parseSourceFilters(configuration.filters);
  const isEntityMatchesFilters = await isStixMatchFilterGroup(context, AUTOMATION_MANAGER_USER, stixEntity, filtersOnSource);
  if (!isEntityMatchesFilters) return;
  const def = JSON.parse(playbook.playbook_definition) as ComponentDefinition;
  const connector = PLAYBOOK_COMPONENTS[instance.component_id];
  const bundle: StixBundle = {
    id: uuidv4(),
    spec_version: STIX_SPEC_VERSION,
    type: 'bundle',
    objects: [stixEntity],
  };
  await playbookExecutor({
    eventId,
    executionId: uuidv4(),
    playbookId: playbook.id,
    dataInstanceId: stixEntity.id,
    definition: def,
    previousStep: null,
    nextStep: { component: connector, instance },
    previousStepBundle: null,
    bundle,
    event: streamEvent.data,
  });
};
