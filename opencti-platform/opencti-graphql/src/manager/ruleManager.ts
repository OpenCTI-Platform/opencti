/* eslint-disable camelcase */
import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { buildEvent, createStreamProcessor, lockResource } from '../database/redis';
import conf, { DEV_MODE, ENABLED_RULE_ENGINE, logApp } from '../config/conf';
import {
  createEntity,
  internalLoadById,
  patchAttribute,
  stixLoadById,
  storeLoadByIdWithRefs,
} from '../database/middleware';
import { isEmptyField, isNotEmptyField, READ_DATA_INDICES } from '../database/utils';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { RULE_PREFIX } from '../schema/general';
import { ENTITY_TYPE_RULE, ENTITY_TYPE_RULE_MANAGER, ENTITY_TYPE_TASK } from '../schema/internalObject';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { createRuleTask, deleteTask } from '../domain/task';
import { RULE_MANAGER_USER, RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules';
import { MIN_LIVE_STREAM_EVENT_VERSION } from '../graphql/sseMiddleware';
import { getParentTypes } from '../schema/schemaUtils';
import { extractFieldsOfPatch, rebuildInstanceBeforePatch } from '../utils/patch';
import { isBasicRelationship } from '../schema/stixRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { elList, listEntities } from '../database/middleware-loader';
import { SYSTEM_USER } from '../utils/access';
// Import all rules
import AttributedToAttributedRule from '../rules/attributed-to-attributed/AttributedToAttributedRule';
import AttributionTargetsRule from '../rules/attribution-targets/AttributionTargetsRule';
import AttributionUseRule from '../rules/attribution-use/AttributionUseRule';
import RuleLocalizationOfTargets from '../rules/localization-of-targets/LocalizationOfTargetsRule';
import LocatedAtLocatedRule from '../rules/located-at-located/LocatedAtLocatedRule';
import LocationTargetsRule from '../rules/location-targets/LocationTargetsRule';
import RuleObservableRelatedObservable from '../rules/observable-related/ObservableRelatedRule';
import PartOfPartRule from '../rules/part-of-part/PartOfPartRule';
import PartOfTargetsRule from '../rules/part-of-targets/PartOfTargetsRule';
import RelatedToRelatedRule from '../rules/related-to-related/RelatedToRelatedRule';
import RuleSightingIncident from '../rules/sighting-incident/SightingIncidentRule';
import RuleObserveSighting from '../rules/observed-sighting/ObserveSightingRule';
import type { Rule, RuleDefinition } from '../types/rules';
import type {
  BasicManagerEntity,
  BasicRuleEntity, BasicStoreCommon,
  BasicTaskEntity,
} from '../types/store';
import type { AuthUser } from '../types/user';
import type { RuleManager } from '../generated/graphql';
import type { StixCoreObject, StixId } from '../types/stix-common';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import type { Event, RuntimeEvent, StreamEvent } from '../types/event';

let activatedRules: Array<Rule> = [];
const RULE_ENGINE_ID = 'rule_engine_settings';
const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');
const STATUS_WRITE_RANGE = conf.get('rule_engine:status_writing_delay') || 500;
const SCHEDULE_TIME = 10000;

// region rules registration
export const RULES_DECLARATION: Array<Rule> = [
  AttributedToAttributedRule,
  AttributionTargetsRule,
  AttributionUseRule,
  RuleLocalizationOfTargets,
  LocatedAtLocatedRule,
  LocationTargetsRule,
  RuleObservableRelatedObservable,
  RuleObserveSighting,
  PartOfPartRule,
  PartOfTargetsRule,
  RuleSightingIncident,
];
if (DEV_MODE) {
  RULES_DECLARATION.push(RelatedToRelatedRule);
}
const ruleBehaviors = RULES_DECLARATION.map((d) => d.behaviors ?? []).flat();
for (let index = 0; index < ruleBehaviors.length; index += 1) {
  const ruleBehavior = ruleBehaviors[index];
  RULES_ATTRIBUTES_BEHAVIOR.register(ruleBehavior);
}
// endregion

// region loaders
export const getRules = async (): Promise<Array<Rule>> => {
  const args = { connectionFormat: false };
  const rules = await listEntities<BasicRuleEntity>(SYSTEM_USER, [ENTITY_TYPE_RULE], args);
  return RULES_DECLARATION.map((def: Rule) => {
    const esRule = rules.find((e) => e.internal_id === def.id);
    const isActivated = esRule?.active === true;
    return { ...def, activated: isActivated };
  });
};

export const getActivatedRules = async (): Promise<Array<Rule>> => {
  const rules = await getRules();
  return rules.filter((r) => r.activated);
};

export const getRule = async (id: string): Promise<RuleDefinition | undefined> => {
  const rules = await getRules();
  return rules.find((e) => e.id === id);
};
// endregion

export const getManagerInfo = async (user: AuthUser): Promise<RuleManager> => {
  const ruleStatus = await internalLoadById(user, RULE_ENGINE_ID) as unknown as BasicManagerEntity;
  return { activated: ENABLED_RULE_ENGINE, ...ruleStatus };
};

export const setRuleActivation = async (user: AuthUser, ruleId: string, active: boolean): Promise<RuleDefinition | undefined> => {
  const resolvedRule = await getRule(ruleId);
  if (isEmptyField(resolvedRule)) {
    throw UnsupportedError(`Cant ${active ? 'enable' : 'disable'} undefined rule ${ruleId}`);
  }
  // Update the rule
  await createEntity(user, { internal_id: ruleId, active, update: true }, ENTITY_TYPE_RULE);
  // Refresh the activated rules
  activatedRules = await getActivatedRules();
  if (ENABLED_RULE_ENGINE) {
    const tasksFilters = [
      { key: 'type', values: ['RULE'] },
      { key: 'rule', values: [ruleId] },
    ];
    const args = { filters: tasksFilters, connectionFormat: false };
    const tasks = await listEntities<BasicTaskEntity>(user, [ENTITY_TYPE_TASK], args);
    await Promise.all(tasks.map((t) => deleteTask(user, t.internal_id)));
    await createRuleTask(user, resolvedRule, { rule: ruleId, enable: active });
  }
  return getRule(ruleId);
};

const buildInternalEvent = (type: string, instance: StixCoreObject): Event => {
  return buildEvent(type, RULE_MANAGER_USER, instance.object_marking_refs ?? [], '-', instance) as Event;
};
const ruleMergeHandler = async (event: Event): Promise<Array<Event>> => {
  const { data, markings } = event;
  const events = [];
  // region 01 - Generate events for deletion
  // -- sources
  const { extensions } = data;
  const x_opencti_context = extensions[STIX_EXT_OCTI].context;
  const sourceDeleteEvents = (x_opencti_context?.sources || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...sourceDeleteEvents);
  // -- derived deletions
  const derivedDeleteEvents = (x_opencti_context?.deletions || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...derivedDeleteEvents);
  // endregion
  // region 02 - Generate events for shifted relations
  if ((x_opencti_context?.shifts ?? []).length > 0) {
    const shifts = x_opencti_context?.shifts ?? [];
    for (let index = 0; index < shifts.length; index += 1) {
      const shift = shifts[index];
      const shiftedElement = await stixLoadById(RULE_MANAGER_USER, shift.id) as StixCoreObject;
      // We need to cleanup the element associated with this relation and then rescan it
      events.push(buildInternalEvent(EVENT_TYPE_DELETE, shiftedElement));
      // Then we need to generate event for redo rule on shifted relations
      events.push(buildInternalEvent(EVENT_TYPE_CREATE, shiftedElement));
    }
  }
  // endregion
  // region 03 - Generate event for merged entity
  const updateEvent = buildEvent(EVENT_TYPE_UPDATE, RULE_MANAGER_USER, markings, '-', data);
  events.push(updateEvent);
  // endregion
  return events;
};

const isAttributesImpactDependencies = (rules: Array<RuleDefinition>, instance: StixCoreObject): boolean => {
  const rulesAttributes = rules
    .map((r) => r.scopes ?? [])
    .flat()
    .map((s) => s.attributes)
    .flat()
    .filter((a) => a.dependency === true)
    .map((a) => a.name);
  const patchedAttributes = Object.entries(instance).map(([k]) => k);
  return patchedAttributes.some((f) => rulesAttributes.includes(f));
};

const isMatchRuleFilters = (rule: RuleDefinition, element: StixCoreObject, matchUpdateFields = false): boolean => {
  // Handle types filtering
  const scopeFilters = rule.scopes ?? [];
  for (let index = 0; index < scopeFilters.length; index += 1) {
    const scopeFilter = scopeFilters[index];
    const { filters, attributes } = scopeFilter;
    const { types = [], fromTypes = [], toTypes = [] } = filters ?? {};
    let isValidFilter = true;
    const instanceType = element.extensions[STIX_EXT_OCTI].type;
    if (types.length > 0) {
      const elementTypes = [instanceType, ...getParentTypes(instanceType)];
      const isCompatibleType = types.some((r) => elementTypes.includes(r));
      if (!isCompatibleType) isValidFilter = false;
    }
    if (isBasicRelationship(instanceType)) {
      const isSighting = isStixSightingRelationship(instanceType);
      let fromType;
      let toType;
      if (isSighting) {
        const sighting = element as StixSighting;
        fromType = sighting.extensions[STIX_EXT_OCTI].sighting_of_type;
        toType = R.head(sighting.extensions[STIX_EXT_OCTI].where_sighted_types);
      } else {
        const relation = element as StixRelation;
        fromType = relation.extensions[STIX_EXT_OCTI].source_type;
        toType = relation.extensions[STIX_EXT_OCTI].target_type;
      }
      if (fromTypes.length > 0) {
        const instanceFromTypes = [fromType, ...getParentTypes(fromType)];
        const isCompatibleType = fromTypes.some((r) => instanceFromTypes.includes(r));
        if (!isCompatibleType) isValidFilter = false;
      }
      if (toTypes.length > 0) {
        const instanceToTypes = [toType, ...getParentTypes(toType)];
        const isCompatibleType = toTypes.some((r) => instanceToTypes.includes(r));
        if (!isCompatibleType) isValidFilter = false;
      }
    }
    if (isValidFilter) {
      if (matchUpdateFields) {
        const { patch } = element.extensions[STIX_EXT_OCTI];
        if (patch === undefined) throw new Error('//TODO JRI CHANGE THAT');
        const patchedFields = extractFieldsOfPatch(patch);
        return attributes.map((a) => a.name).some((f) => patchedFields.includes(f));
      }
      return true;
    }
  }
  // No filter match, return false
  return false;
};

const handleRuleError = async (event: Event, error: unknown) => {
  const { type } = event;
  logApp.error(`[OPENCTI-MODULE] Rule error applying ${type} event`, { event, error });
};

const applyCleanupOnDependencyIds = async (eventId: string, deletionIds: Array<string>) => {
  const filters = [{ key: `${RULE_PREFIX}*.dependencies`, values: deletionIds, operator: 'wildcard' }];
  const callback = (elements: Array<BasicStoreCommon>) => {
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
    return rulesCleanHandler(eventId, elements, RULES_DECLARATION, deletionIds);
  };
  await elList<BasicStoreCommon>(RULE_MANAGER_USER, READ_DATA_INDICES, { filters, callback });
};

// noinspection TypeScriptValidateTypes
export const rulesApplyHandler = async (events: Array<RuntimeEvent>, forRules: Array<Rule> = []) => {
  if (isEmptyField(events) || events.length === 0) return;
  const rules = forRules.length > 0 ? forRules : activatedRules;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const { eventId, type, data, markings } = event;
    logApp.debug('[RULE] Processing event', { eventId });
    try {
      const element: StixCoreObject = { ...data, object_marking_refs: markings };
      const internalId = data.extensions[STIX_EXT_OCTI].id;
      // In case of merge convert the events to basic events and restart the process
      if (type === EVENT_TYPE_MERGE) {
        const derivedEvents = await ruleMergeHandler(event);
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        await rulesApplyDerivedEvents(eventId, derivedEvents);
      }
      // In case of deletion, call clean on every impacted elements
      if (type === EVENT_TYPE_DELETE) {
        const contextDeletions = (data.extensions[STIX_EXT_OCTI].context?.deletions ?? [])
          .map((d) => d.extensions[STIX_EXT_OCTI].id);
        const deletionIds = [internalId, ...contextDeletions];
        await applyCleanupOnDependencyIds(eventId, deletionIds);
      }
      // In case of update apply the event on every rules
      if (type === EVENT_TYPE_UPDATE) {
        // We need to clean elements that could be part of rule dependencies
        // Only interesting if rule depends of this patched attributes
        const { patch } = element.extensions[STIX_EXT_OCTI];
        if (patch === undefined) throw new Error('//TODO JRI CHANGE THAT');
        const previously = rebuildInstanceBeforePatch({}, patch);
        const isDependent = isAttributesImpactDependencies(rules, previously);
        if (isDependent) {
          const deletionIds = Object.entries(previously).map(([k, v]) => `${internalId}_${k}:${v}`);
          await applyCleanupOnDependencyIds(eventId, deletionIds);
        }
        // Dispatch update
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          const isImpactedElement = isMatchRuleFilters(rule, element, true);
          if (isImpactedElement) {
            const elementId: StixId = patch?.replace?.id || element.id;
            const stixData = await stixLoadById(RULE_MANAGER_USER, elementId);
            const derivedEvents = await rule.update(stixData);
            // eslint-disable-next-line @typescript-eslint/no-use-before-define
            await rulesApplyDerivedEvents(eventId, derivedEvents);
          }
        }
      }
      // In case of creation apply the event on every rules
      if (type === EVENT_TYPE_CREATE) {
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          const isImpactedElement = isMatchRuleFilters(rule, element);
          if (isImpactedElement) {
            const derivedEvents = await rule.insert(element);
            // eslint-disable-next-line @typescript-eslint/no-use-before-define
            await rulesApplyDerivedEvents(eventId, derivedEvents);
          }
        }
      }
    } catch (e) {
      await handleRuleError(event, e);
    }
  }
};

export const rulesApplyDerivedEvents = async (eventId: string, derivedEvents: Array<Event>, forRules: Array<Rule> = []): Promise<void> => {
  const events = derivedEvents.map((d) => ({ eventId, ...d }));
  // eslint-disable-next-line no-use-before-define
  await rulesApplyHandler(events, forRules);
};

export const rulesCleanHandler = async (eventId: string, instances: Array<BasicStoreCommon>, rules: Array<Rule>, deletedDependencies: Array<string> = []) => {
  for (let i = 0; i < instances.length; i += 1) {
    const instance = instances[i];
    for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
      const rule = rules[ruleIndex];
      const isElementCleanable = isNotEmptyField(instance[`${RULE_PREFIX}${rule.id}`]);
      if (isElementCleanable) {
        const processingElement: StixCoreObject = await storeLoadByIdWithRefs(RULE_MANAGER_USER, instance.internal_id);
        // In case of inference of inference, element can be recursively cleanup by the deletion system
        if (processingElement) {
          const derivedEvents = await rule.clean(processingElement, deletedDependencies);
          await rulesApplyDerivedEvents(eventId, derivedEvents);
        }
      }
    }
  }
};

let streamEventProcessedCount = 0;
const ruleStreamHandler = async (streamEvents: Array<StreamEvent>) => {
  // Create list of events to process
  // Events must be in a compatible version and not inferences events
  // Inferences directly handle recursively by the manager
  const compatibleEvents = streamEvents.filter((event) => {
    const eventVersion = parseInt(event.data?.version ?? '0', 10);
    const isCompatibleVersion = eventVersion >= MIN_LIVE_STREAM_EVENT_VERSION;
    const isInferenceEvent = event.data?.data?.extensions[STIX_EXT_OCTI].is_inferred ?? false;
    return isCompatibleVersion && !isInferenceEvent;
  });
  if (compatibleEvents.length > 0) {
    const ruleEvents: Array<RuntimeEvent> = compatibleEvents.map((e) => {
      const { id, data: eventData } = e;
      return { eventId: `stream--${id}`, ...eventData };
    });
    // Execute the events
    await rulesApplyHandler(ruleEvents);
    // Save the last processed event
    if (streamEventProcessedCount > STATUS_WRITE_RANGE) {
      const lastEvent = R.last(compatibleEvents);
      const patch = { lastEventId: lastEvent?.id };
      await patchAttribute(RULE_MANAGER_USER, RULE_ENGINE_ID, ENTITY_TYPE_RULE_MANAGER, patch);
      streamEventProcessedCount = 0;
    } else {
      streamEventProcessedCount += compatibleEvents.length;
    }
  }
};

const getInitRuleManager = () => {
  const ruleSettingsInput = { internal_id: RULE_ENGINE_ID, errors: [] };
  return createEntity(RULE_MANAGER_USER, ruleSettingsInput, ENTITY_TYPE_RULE_MANAGER);
};

const initRuleManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer;
  let streamProcessor;
  let syncListening = true;
  const wait = (ms: number) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const ruleHandler = async (lastEventId: string) => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([RULE_ENGINE_KEY]);
      logApp.info('[OPENCTI-MODULE] Running rule manager');
      // Start the stream listening
      activatedRules = await getActivatedRules();
      streamProcessor = createStreamProcessor(RULE_MANAGER_USER, 'Rule manager', ruleStreamHandler);
      await streamProcessor.start(lastEventId);
      while (syncListening) {
        await wait(WAIT_TIME_ACTION);
      }
      await streamProcessor.shutdown();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.info('[OPENCTI-MODULE] Rule engine already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Rule engine failed to start', { error: e });
      }
    } finally {
      if (lock) await lock.unlock();
    }
  };
  const shutdown = async () => {
    syncListening = false;
    if (scheduler) {
      return clearIntervalAsync(scheduler);
    }
    return true;
  };
  return {
    start: async () => {
      const ruleManager = await getInitRuleManager();
      scheduler = setIntervalAsync(async () => {
        await ruleHandler(ruleManager.lastEventId);
      }, SCHEDULE_TIME);
    },
    shutdown,
  };
};
const ruleEngine = initRuleManager();

export const cleanRuleManager = async (user: AuthUser, eventId: string) => {
  // Clear the elastic status
  const patch = { lastEventId: eventId, errors: [] };
  const { element } = await patchAttribute(user, RULE_ENGINE_ID, ENTITY_TYPE_RULE_MANAGER, patch);
  // Restart the manager
  await ruleEngine.shutdown();
  await ruleEngine.start();
  // Return the updated element
  return { activated: ENABLED_RULE_ENGINE, ...element };
};

export default ruleEngine;
