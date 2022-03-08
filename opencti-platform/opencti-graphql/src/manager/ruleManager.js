/* eslint-disable camelcase */
import * as R from 'ramda';
import { clearIntervalAsync, setIntervalAsync } from 'set-interval-async/fixed';
import { buildEvent, createStreamProcessor, lockResource } from '../database/redis';
import conf, { DEV_MODE, ENABLED_RULE_ENGINE, logApp } from '../config/conf';
import {
  createEntity,
  internalLoadById,
  patchAttribute,
  loadStixById, loadByIdWithMetaRels,
} from '../database/middleware';
import { isEmptyField, isNotEmptyField, READ_DATA_INDICES } from '../database/utils';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { elList } from '../database/engine';
import { RULE_PREFIX } from '../schema/general';
import { ENTITY_TYPE_RULE, ENTITY_TYPE_RULE_MANAGER } from '../schema/internalObject';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { createRuleTask, deleteTask, findAll } from '../domain/task';
import { RULE_MANAGER_USER, RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules';
import { MIN_LIVE_STREAM_EVENT_VERSION } from '../graphql/sseMiddleware';
import { getParentTypes } from '../schema/schemaUtils';
import { extractFieldsOfPatch, rebuildInstanceBeforePatch } from '../utils/patch';
import { isBasicRelationship } from '../schema/stixRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { listEntities } from '../database/repository';
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

let activatedRules = [];
const RULE_ENGINE_ID = 'rule_engine_settings';
const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');
const STATUS_WRITE_RANGE = conf.get('rule_engine:status_writing_delay') || 500;
const SCHEDULE_TIME = 10000;

// region rules registration
export const RULES_DECLARATION = [
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
export const getRules = async () => {
  const args = { connectionFormat: false };
  const rules = await listEntities(SYSTEM_USER, [ENTITY_TYPE_RULE], args);
  return RULES_DECLARATION.map((d) => {
    const esRule = R.find((e) => e.internal_id === d.id)(rules);
    const isActivated = isNotEmptyField(esRule) && esRule.active;
    return { ...d, activated: isActivated };
  });
};

export const getActivatedRules = async () => {
  const rules = await getRules();
  return rules.filter((r) => r.activated);
};

export const getRule = async (id) => {
  const rules = await getRules();
  return R.find((e) => e.id === id)(rules);
};
// endregion

export const getManagerInfo = async (user) => {
  const ruleStatus = await internalLoadById(user, RULE_ENGINE_ID);
  return { activated: ENABLED_RULE_ENGINE, ...ruleStatus };
};

export const setRuleActivation = async (user, ruleId, active) => {
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
    const tasks = await findAll(user, { filters: tasksFilters, connectionFormat: false });
    await Promise.all(tasks.map((t) => deleteTask(user, t.id)));
    await createRuleTask(user, resolvedRule, { rule: ruleId, enable: active });
  }
  return getRule(ruleId);
};

const buildInternalEvent = (type, instance) => {
  return buildEvent(type, RULE_MANAGER_USER, instance.object_marking_refs ?? [], '-', instance);
};
const ruleMergeHandler = async (event) => {
  const { data, markings } = event;
  const events = [];
  // region 01 - Generate events for deletion
  // -- sources
  const { x_opencti_context } = data;
  const sourceDeleteEvents = x_opencti_context.sources.map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...sourceDeleteEvents);
  // -- derived deletions
  const derivedDeleteEvents = x_opencti_context.deletions.map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...derivedDeleteEvents);
  // endregion
  // region 02 - Generate events for shifted relations
  // We need to cleanup the element associated with this relation and then rescan it
  if (x_opencti_context.shifts.length > 0) {
    const shiftDeleteEvents = x_opencti_context.shifts.map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
    events.push(...shiftDeleteEvents);
    // Then we need to generate event for redo rule on updated element
    const shiftRescanEvents = x_opencti_context.shifts.map((s) => buildInternalEvent(EVENT_TYPE_UPDATE, s));
    events.push(...shiftRescanEvents);
  }
  // endregion
  // region 03 - Generate event for merged entity
  const updateEvent = buildEvent(EVENT_TYPE_UPDATE, RULE_MANAGER_USER, markings, '-', data);
  events.push(updateEvent);
  // endregion
  return events;
};

const isAttributesImpactDependencies = (rules, instance) => {
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

const isMatchRuleFilters = (rule, element, matchUpdateFields = false) => {
  // Handle types filtering
  const scopeFilters = rule.scopes ?? [];
  for (let index = 0; index < scopeFilters.length; index += 1) {
    const scopeFilter = scopeFilters[index];
    const { filters, attributes } = scopeFilter;
    const { types = [], fromTypes = [], toTypes = [] } = filters ?? {};
    let isValidFilter = true;
    if (types.length > 0) {
      const instanceType = element.x_opencti_type;
      const elementTypes = [instanceType, ...getParentTypes(instanceType)];
      const isCompatibleType = types.some((r) => elementTypes.includes(r));
      if (!isCompatibleType) isValidFilter = false;
    }
    if (isBasicRelationship(element.x_opencti_type)) {
      const isSighting = isStixSightingRelationship(element.x_opencti_type);
      if (fromTypes.length > 0) {
        const fromType = isSighting ? element.x_opencti_sighting_of_type : element.x_opencti_source_type;
        const instanceFromTypes = [fromType, ...getParentTypes(fromType)];
        const isCompatibleType = fromTypes.some((r) => instanceFromTypes.includes(r));
        if (!isCompatibleType) isValidFilter = false;
      }
      if (toTypes.length > 0) {
        const toType = isSighting ? R.head(element.x_opencti_where_sighted_types) : element.x_opencti_target_type;
        const instanceToTypes = [toType, ...getParentTypes(toType)];
        const isCompatibleType = toTypes.some((r) => instanceToTypes.includes(r));
        if (!isCompatibleType) isValidFilter = false;
      }
    }
    if (isValidFilter) {
      if (matchUpdateFields) {
        const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
        return attributes.map((a) => a.name).some((f) => patchedFields.includes(f));
      }
      return true;
    }
  }
  // No filter match, return false
  return false;
};

const handleRuleError = async (event, error) => {
  const { type } = event;
  logApp.error(`[OPENCTI-MODULE] Rule error applying ${type} event`, { event, error });
};

export const rulesApplyDerivedEvents = async (eventId, derivedEvents, forRules = []) => {
  const events = derivedEvents.map((d) => ({ eventId, ...d }));
  // eslint-disable-next-line no-use-before-define
  await rulesApplyHandler(events, forRules);
};

const applyCleanupOnDependencyIds = async (eventId, deletionIds) => {
  const filters = [{ key: `${RULE_PREFIX}*.dependencies`, values: deletionIds, operator: 'wildcard' }];
  const callback = (elements) => {
    // eslint-disable-next-line no-use-before-define
    return rulesCleanHandler(eventId, elements, RULES_DECLARATION, deletionIds);
  };
  await elList(RULE_MANAGER_USER, READ_DATA_INDICES, { filters, callback });
};

export const rulesApplyHandler = async (events, forRules = []) => {
  if (isEmptyField(events) || events.length === 0) return;
  const rules = forRules.length > 0 ? forRules : activatedRules;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const { eventId, type, data, markings } = event;
    logApp.debug('[RULE] Processing event', { eventId });
    try {
      const element = { ...data, object_marking_refs: markings };
      // In case of merge convert the events to basic events and restart the process
      if (type === EVENT_TYPE_MERGE) {
        const derivedEvents = await ruleMergeHandler(event);
        await rulesApplyDerivedEvents(eventId, derivedEvents);
      }
      // In case of deletion, call clean on every impacted elements
      if (type === EVENT_TYPE_DELETE) {
        const contextDeletions = (data.x_opencti_context?.deletions ?? []).map((d) => d.x_opencti_id);
        const deletionIds = [data.x_opencti_id, ...contextDeletions];
        await applyCleanupOnDependencyIds(eventId, deletionIds);
      }
      // In case of update apply the event on every rules
      if (type === EVENT_TYPE_UPDATE) {
        // We need to clean elements that could be part of rule dependencies
        // Only interesting if rule depends of this patched attributes
        const previously = rebuildInstanceBeforePatch({}, element.x_opencti_patch);
        const isDependent = isAttributesImpactDependencies(rules, previously);
        if (isDependent) {
          const deletionIds = Object.entries(previously).map(([k, v]) => `${data.x_opencti_id}_${k}:${v}`);
          await applyCleanupOnDependencyIds(eventId, deletionIds);
        }
        // Dispatch update
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          const isImpactedElement = isMatchRuleFilters(rule, element, true);
          if (isImpactedElement) {
            let elementId = element.id;
            const patchedFields = extractFieldsOfPatch(element.x_opencti_patch);
            // If id is changed
            if (patchedFields.includes('id')) {
              elementId = element.x_opencti_patch.replace.id.current;
            }
            const stixData = await loadStixById(RULE_MANAGER_USER, elementId);
            const derivedEvents = await rule.update(stixData, patchedFields);
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
            await rulesApplyDerivedEvents(eventId, derivedEvents);
          }
        }
      }
    } catch (e) {
      await handleRuleError(event, e);
    }
  }
};

export const rulesCleanHandler = async (eventId, instances, rules, deletedDependencies = []) => {
  for (let i = 0; i < instances.length; i += 1) {
    const instance = instances[i];
    for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
      const rule = rules[ruleIndex];
      const isElementCleanable = isNotEmptyField(instance[RULE_PREFIX + rule.id]);
      if (isElementCleanable) {
        const processingElement = await loadByIdWithMetaRels(RULE_MANAGER_USER, instance.internal_id);
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
const ruleStreamHandler = async (streamEvents) => {
  // Create list of events to process
  // Events must be in a compatible version and not inferences events
  // Inferences directly handle recursively by the manager
  const compatibleEvents = streamEvents.filter((event) => {
    const eventVersion = parseInt(event.data?.version ?? '0', 10);
    const isCompatibleVersion = eventVersion >= MIN_LIVE_STREAM_EVENT_VERSION;
    const isInferenceEvent = event.data?.data?.x_opencti_inference ?? false;
    return isCompatibleVersion && !isInferenceEvent;
  });
  if (compatibleEvents.length > 0) {
    const ruleEvents = compatibleEvents.map((e) => {
      const { id, topic, data: eventData } = e;
      const { data, markings } = eventData;
      return { eventId: `stream--${id}`, type: topic, markings, data };
    });
    // Execute the events
    await rulesApplyHandler(ruleEvents);
    // Save the last processed event
    if (streamEventProcessedCount > STATUS_WRITE_RANGE) {
      const lastEvent = R.last(compatibleEvents);
      const patch = { lastEventId: lastEvent.id };
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
  let scheduler;
  let streamProcessor;
  let syncListening = true;
  const wait = (ms) => {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
  };
  const ruleHandler = async () => {
    let lock;
    try {
      // Lock the manager
      lock = await lockResource([RULE_ENGINE_KEY]);
      logApp.info('[OPENCTI-MODULE] Running rule manager');
      // Start the stream listening
      const ruleManager = await getInitRuleManager();
      activatedRules = await getActivatedRules();
      streamProcessor = createStreamProcessor(RULE_MANAGER_USER, 'Rule manager', ruleStreamHandler);
      await streamProcessor.start(ruleManager.lastEventId);
      while (syncListening) {
        await wait(WAIT_TIME_ACTION);
      }
      await streamProcessor.shutdown();
    } catch (e) {
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
      await getInitRuleManager();
      scheduler = setIntervalAsync(async () => {
        await ruleHandler();
      }, SCHEDULE_TIME);
    },
    shutdown,
  };
};
const ruleEngine = initRuleManager();

export const cleanRuleManager = async (user, eventId) => {
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
