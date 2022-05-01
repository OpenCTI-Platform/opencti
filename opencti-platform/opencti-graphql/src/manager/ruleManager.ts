/* eslint-disable camelcase */
import * as R from 'ramda';
import type { Operation } from 'fast-json-patch';
import * as jsonpatch from 'fast-json-patch';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createStreamProcessor, EVENT_VERSION_V4, lockResource } from '../database/redis';
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
import type { RuleDefinition, RuleRuntime, RuleScope } from '../types/rules';
import type {
  BasicManagerEntity,
  BasicRuleEntity,
  BasicStoreCommon,
  BasicStoreEntity,
  BasicTaskEntity,
} from '../types/store';
import type { AuthUser } from '../types/user';
import type { RuleManager } from '../generated/graphql';
import type { StixCoreObject } from '../types/stix-common';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import type { DeleteEvent, Event, MergeEvent, StreamEvent, UpdateEvent } from '../types/event';

// let activatedRules: Array<RuleRuntime> = [];
const RULE_ENGINE_ID = 'rule_engine_settings';
const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');
const STATUS_WRITE_RANGE = conf.get('rule_engine:status_writing_delay') || 500;
const SCHEDULE_TIME = 10000;

// region rules registration
export const RULES_DECLARATION: Array<RuleRuntime> = [
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
export const getRules = async (): Promise<Array<RuleRuntime>> => {
  const args = { connectionFormat: false };
  const rules = await listEntities<BasicRuleEntity>(SYSTEM_USER, [ENTITY_TYPE_RULE], args);
  return RULES_DECLARATION.map((def: RuleRuntime) => {
    const esRule = rules.find((e) => e.internal_id === def.id);
    const isActivated = esRule?.active === true;
    return { ...def, activated: isActivated };
  });
};

export const getActivatedRules = async (): Promise<Array<RuleRuntime>> => {
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
  // activatedRules = await getActivatedRules();
  if (ENABLED_RULE_ENGINE) {
    const tasksFilters = [{ key: 'type', values: ['RULE'] }, { key: 'rule', values: [ruleId] }];
    const args = { filters: tasksFilters, connectionFormat: false };
    const tasks = await listEntities<BasicTaskEntity>(user, [ENTITY_TYPE_TASK], args);
    await Promise.all(tasks.map((t) => deleteTask(user, t.internal_id)));
    await createRuleTask(user, resolvedRule, { rule: ruleId, enable: active });
  }
  return getRule(ruleId);
};

const buildInternalEvent = (type: string, stix: StixCoreObject): Event => {
  return {
    version: EVENT_VERSION_V4,
    type,
    message: 'rule internal event',
    origin: RULE_MANAGER_USER,
    data: stix,
  };
};

const ruleMergeHandler = async (event: MergeEvent): Promise<Array<Event>> => {
  const { data, context } = event;
  const events: Array<Event> = [];
  // region 01 - Generate events for deletion
  // -- sources
  const sourceDeleteEvents = (context?.sources || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...sourceDeleteEvents);
  // -- derived deletions
  const derivedDeleteEvents = (context?.deletions || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...derivedDeleteEvents);
  // endregion
  // region 02 - Generate events for shifted relations
  if ((context?.shifts ?? []).length > 0) {
    const shifts = context?.shifts ?? [];
    for (let index = 0; index < shifts.length; index += 1) {
      const shift = shifts[index];
      const shiftedElement = await stixLoadById(RULE_MANAGER_USER, shift) as StixCoreObject;
      // We need to cleanup the element associated with this relation and then rescan it
      events.push(buildInternalEvent(EVENT_TYPE_DELETE, shiftedElement));
      // Then we need to generate event for redo rule on shifted relations
      events.push(buildInternalEvent(EVENT_TYPE_CREATE, shiftedElement));
    }
  }
  // endregion
  // region 03 - Generate event for merged entity
  const updateEvent = buildInternalEvent(EVENT_TYPE_UPDATE, data) as UpdateEvent;
  updateEvent.context = { previous_patch: context.previous_patch };
  events.push(updateEvent);
  // endregion
  return events;
};

const isAttributesImpactDependencies = (rule: RuleDefinition, operations: Operation[]): boolean => {
  const rulesAttributes = (rule.scopes ?? [])
    .map((s) => s.attributes)
    .flat()
    .filter((a) => a.dependency === true)
    .map((a) => a.name);
  const operationAttributes = R.uniq(operations.map((o) => {
    const parts = o.path.substring(1).split('/');
    // eslint-disable-next-line no-restricted-globals
    return parts.filter((p) => isNaN(Number(p))).join('.');
  }));
  return operationAttributes.filter((f) => rulesAttributes.includes(f)).length > 0;
};

const isMatchRuleScope = (scopeFilter: RuleScope, element: StixCoreObject): boolean => {
  const { filters } = scopeFilter;
  const { types = [], fromTypes = [], toTypes = [] } = filters ?? {};
  const instanceType = element.extensions[STIX_EXT_OCTI].type;
  if (types.length > 0) {
    const elementTypes = [instanceType, ...getParentTypes(instanceType)];
    const isCompatibleType = types.some((r) => elementTypes.includes(r));
    if (!isCompatibleType) {
      return false;
    }
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
      if (!isCompatibleType) {
        return false;
      }
    }
    if (toTypes.length > 0) {
      const instanceToTypes = [toType, ...getParentTypes(toType)];
      const isCompatibleType = toTypes.some((r) => instanceToTypes.includes(r));
      if (!isCompatibleType) {
        return false;
      }
    }
  }
  return true;
};

const isMatchRuleFilters = (rule: RuleDefinition, element: StixCoreObject): boolean => {
  // Handle types filtering
  const evaluations = [];
  const scopeFilters = rule.scopes ?? [];
  for (let index = 0; index < scopeFilters.length; index += 1) {
    const scopeFilter = scopeFilters[index];
    evaluations.push(isMatchRuleScope(scopeFilter, element));
  }
  // All filters are valid
  return evaluations.reduce((a, b) => a || b);
};

const handleRuleError = async (event: Event, error: unknown) => {
  const { type } = event;
  logApp.error(`[OPENCTI-MODULE] Rule error applying ${type} event`, { event, error });
};

const applyCleanupOnDependencyIds = async (deletionIds: Array<string>) => {
  const filters = [{ key: `${RULE_PREFIX}*.dependencies`, values: deletionIds, operator: 'wildcard' }];
  const callback = (elements: Array<BasicStoreCommon>) => {
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
    return rulesCleanHandler(elements, RULES_DECLARATION, deletionIds);
  };
  await elList<BasicStoreCommon>(RULE_MANAGER_USER, READ_DATA_INDICES, { filters, callback });
};

export const rulesApplyHandler = async (events: Array<Event>, forRules: Array<RuleRuntime> = []) => {
  if (isEmptyField(events) || events.length === 0) {
    return;
  }
  // TODO JRI Find a way to prevent fetch every times (distributed configuration)
  const rules = forRules.length > 0 ? forRules : await getActivatedRules();
  // Keep only compatible events
  const compatibleEvents = events.filter((e) => e.version === EVENT_VERSION_V4);
  // Execute the events
  for (let index = 0; index < compatibleEvents.length; index += 1) {
    const event = compatibleEvents[index];
    const { type, data } = event;
    const internalId = data.extensions[STIX_EXT_OCTI].id;
    try {
      // In case of merge convert the events to basic events and restart the process
      if (type === EVENT_TYPE_MERGE) {
        const mergeEvent = event as MergeEvent;
        const derivedEvents = await ruleMergeHandler(mergeEvent);
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        await rulesApplyHandler(derivedEvents);
      }
      // In case of deletion, call clean on every impacted elements
      if (type === EVENT_TYPE_DELETE) {
        const deleteEvent = event as DeleteEvent;
        // const element: StixCoreObject = { ...data, object_marking_refs: markings };
        const contextDeletions = (deleteEvent.context?.deletions ?? []).map((d) => d.extensions[STIX_EXT_OCTI].id);
        const deletionIds = [internalId, ...contextDeletions];
        await applyCleanupOnDependencyIds(deletionIds);
      }
      // In case of update apply the event on every rules
      if (type === EVENT_TYPE_UPDATE) {
        const updateEvent = event as UpdateEvent;
        const previousPatch = updateEvent.context.previous_patch;
        const previousStix = jsonpatch.applyPatch<StixCoreObject>(R.clone(data), previousPatch).newDocument;
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          // TODO Improve filtering definition to rely on attribute values
          const isPreviouslyMatched = isMatchRuleFilters(rule, previousStix);
          const isCurrentMatched = isMatchRuleFilters(rule, data);
          const impactDependencies = isAttributesImpactDependencies(rule, previousPatch);
          // Rule doesnt match anymore, need to cleanup
          if (impactDependencies || (isPreviouslyMatched && !isCurrentMatched)) {
            await applyCleanupOnDependencyIds([internalId]);
          }
          // Rule match, need to apply
          if (isCurrentMatched) {
            const derivedEvents = await rule.insert(data);
            await rulesApplyHandler(derivedEvents);
          }
        }
      }
      // In case of creation apply the event on every rules
      if (type === EVENT_TYPE_CREATE) {
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          const isImpactedElement = isMatchRuleFilters(rule, data);
          if (isImpactedElement) {
            const derivedEvents = await rule.insert(data);
            await rulesApplyHandler(derivedEvents);
          }
        }
      }
    } catch (e) {
      await handleRuleError(event, e);
    }
  }
};

export const rulesCleanHandler = async (instances: Array<BasicStoreCommon>, rules: Array<RuleRuntime>, deletedDependencies: Array<string> = []) => {
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
          await rulesApplyHandler(derivedEvents);
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
    const ruleEvents: Array<Event> = compatibleEvents.map((e) => e.data);
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

const getInitRuleManager = async (): Promise<BasicStoreEntity> => {
  const ruleSettingsInput = { internal_id: RULE_ENGINE_ID, errors: [] };
  const created = await createEntity(RULE_MANAGER_USER, ruleSettingsInput, ENTITY_TYPE_RULE_MANAGER);
  return created as BasicStoreEntity;
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
      // activatedRules = await getActivatedRules();
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
