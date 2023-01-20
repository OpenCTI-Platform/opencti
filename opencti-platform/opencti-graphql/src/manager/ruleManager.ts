/* eslint-disable camelcase */
import * as R from 'ramda';
import type { Operation } from 'fast-json-patch';
import * as jsonpatch from 'fast-json-patch';
import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import {
  createStreamProcessor,
  EVENT_CURRENT_VERSION,
  lockResource,
  REDIS_STREAM_NAME,
  StreamProcessor
} from '../database/redis';
import conf, { booleanConf, ENABLED_RULE_ENGINE, logApp } from '../config/conf';
import { createEntity, patchAttribute, stixLoadById, storeLoadByIdWithRefs } from '../database/middleware';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_MERGE,
  EVENT_TYPE_UPDATE,
  isEmptyField,
  isNotEmptyField,
  READ_DATA_INDICES
} from '../database/utils';
import { RULE_PREFIX } from '../schema/general';
import { ENTITY_TYPE_RULE_MANAGER } from '../schema/internalObject';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { RULES_ATTRIBUTES_BEHAVIOR } from '../rules/rules';
import { getParentTypes } from '../schema/schemaUtils';
import { isBasicRelationship } from '../schema/stixRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { elList, internalLoadById } from '../database/middleware-loader';
import type { RuleDefinition, RuleRuntime, RuleScope } from '../types/rules';
import type { BasicManagerEntity, BasicStoreCommon, BasicStoreEntity, StoreObject } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import type { RuleManager } from '../generated/graphql';
import type { StixCoreObject } from '../types/stix-common';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import type { StixRelation, StixSighting } from '../types/stix-sro';
import type {
  BaseEvent,
  DataEvent,
  DeleteEvent,
  MergeEvent,
  SseEvent,
  StreamDataEvent,
  UpdateEvent
} from '../types/event';
import { getActivatedRules, RULES_DECLARATION } from '../domain/rules';
import { executionContext, RULE_MANAGER_USER } from '../utils/access';

const MIN_LIVE_STREAM_EVENT_VERSION = 4;

// let activatedRules: Array<RuleRuntime> = [];
const RULE_ENGINE_ID = 'rule_engine_settings';
const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');
const SCHEDULE_TIME = 10000;

// region rules registration
const ruleBehaviors = RULES_DECLARATION.map((d) => d.behaviors ?? []).flat();
for (let index = 0; index < ruleBehaviors.length; index += 1) {
  const ruleBehavior = ruleBehaviors[index];
  RULES_ATTRIBUTES_BEHAVIOR.register(ruleBehavior);
}
// endregion

export const getManagerInfo = async (context: AuthContext, user: AuthUser): Promise<RuleManager> => {
  const ruleStatus = await internalLoadById(context, user, RULE_ENGINE_ID) as unknown as BasicManagerEntity;
  return { activated: ENABLED_RULE_ENGINE, ...ruleStatus };
};

export const buildInternalEvent = (type: 'update' | 'create' | 'delete', stix: StixCoreObject): StreamDataEvent => {
  return {
    version: EVENT_CURRENT_VERSION,
    type,
    scope: 'internal',
    message: 'rule internal event',
    origin: RULE_MANAGER_USER,
    data: stix,
  };
};

const ruleMergeHandler = async (context: AuthContext, event: MergeEvent): Promise<Array<BaseEvent>> => {
  const { data, context: eventContext } = event;
  const events: Array<BaseEvent> = [];
  // region 01 - Generate events for deletion
  // -- sources
  const sourceDeleteEvents = (eventContext.sources || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...sourceDeleteEvents);
  // -- derived deletions
  const derivedDeleteEvents = (eventContext.deletions || []).map((s) => buildInternalEvent(EVENT_TYPE_DELETE, s));
  events.push(...derivedDeleteEvents);
  // endregion
  // region 02 - Generate events for shifted relations
  if ((eventContext.shifts ?? []).length > 0) {
    const shifts = eventContext.shifts ?? [];
    for (let index = 0; index < shifts.length; index += 1) {
      const shift = shifts[index];
      const shiftedElement = await stixLoadById(context, RULE_MANAGER_USER, shift) as StixCoreObject;
      // In past reprocess the shift element can already have been deleted.
      if (shiftedElement) {
        // We need to clean the element associated with this relation and then rescan it
        events.push(buildInternalEvent(EVENT_TYPE_DELETE, shiftedElement));
        // Then we need to generate event for redo rule on shifted relations
        events.push(buildInternalEvent(EVENT_TYPE_CREATE, shiftedElement));
      }
    }
  }
  // endregion
  // region 03 - Generate event for merged entity
  const updateEvent = buildInternalEvent(EVENT_TYPE_UPDATE, data) as UpdateEvent;
  updateEvent.context = { patch: eventContext.patch, reverse_patch: eventContext.reverse_patch };
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

const handleRuleError = async (event: BaseEvent, error: unknown) => {
  const { type } = event;
  logApp.error(`[OPENCTI-MODULE] Rule error applying ${type} event`, { event, error });
};

const applyCleanupOnDependencyIds = async (deletionIds: Array<string>) => {
  const context = executionContext('rule_cleaner', RULE_MANAGER_USER);
  const filters = [{ key: `${RULE_PREFIX}*.dependencies`, values: deletionIds, operator: 'wildcard' }];
  const callback = (elements: Array<BasicStoreCommon>) => {
    // eslint-disable-next-line @typescript-eslint/no-use-before-define
    return rulesCleanHandler(context, RULE_MANAGER_USER, elements, RULES_DECLARATION, deletionIds);
  };
  await elList<BasicStoreCommon>(context, RULE_MANAGER_USER, READ_DATA_INDICES, { filters, callback });
};

export const rulesApplyHandler = async (context: AuthContext, user: AuthUser, events: Array<DataEvent>, forRules: Array<RuleRuntime> = []) => {
  if (isEmptyField(events) || events.length === 0) {
    return;
  }
  const rules = forRules.length > 0 ? forRules : await getActivatedRules(context, user);
  // Execute the events
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const { type, data } = event;
    try {
      // In case of merge convert the events to basic events and restart the process
      if (type === EVENT_TYPE_MERGE) {
        const mergeEvent = event as MergeEvent;
        const mergeEvents = await ruleMergeHandler(context, mergeEvent);
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        await rulesApplyHandler(context, user, mergeEvents);
      }
      // In case of deletion, call clean on every impacted elements
      if (type === EVENT_TYPE_DELETE) {
        const deleteEvent = event as DeleteEvent;
        const internalId = deleteEvent.data.extensions[STIX_EXT_OCTI].id;
        const contextDeletionsIds = (deleteEvent.context?.deletions ?? []).map((d) => d.extensions[STIX_EXT_OCTI].id);
        const deletionIds = [internalId, ...contextDeletionsIds];
        await applyCleanupOnDependencyIds(deletionIds);
      }
      // In case of update apply the event on every rules
      if (type === EVENT_TYPE_UPDATE) {
        const updateEvent = event as UpdateEvent;
        const internalId = updateEvent.data.extensions[STIX_EXT_OCTI].id;
        const previousPatch = updateEvent.context.reverse_patch;
        const previousStix = jsonpatch.applyPatch<StixCoreObject>(R.clone(data), previousPatch).newDocument;
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          // TODO Improve filtering definition to rely on attribute values
          const isPreviouslyMatched = isMatchRuleFilters(rule, previousStix);
          const isCurrentMatched = isMatchRuleFilters(rule, data);
          const impactDependencies = isAttributesImpactDependencies(rule, previousPatch);
          // Rule doesn't match anymore, need to clean up
          if (impactDependencies || (isPreviouslyMatched && !isCurrentMatched)) {
            await applyCleanupOnDependencyIds([internalId]);
          }
          // Rule match, need to apply
          if (isCurrentMatched) {
            await rule.update(data, updateEvent);
          }
        }
      }
      // In case of creation apply the event on every rules
      if (type === EVENT_TYPE_CREATE) {
        for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
          const rule = rules[ruleIndex];
          const isImpactedElement = isMatchRuleFilters(rule, data);
          if (isImpactedElement) {
            await rule.insert(data);
          }
        }
      }
    } catch (e) {
      await handleRuleError(event, e);
    }
  }
};

export const rulesCleanHandler = async (
  context: AuthContext,
  user: AuthUser,
  instances: Array<BasicStoreCommon>,
  rules: Array<RuleRuntime>,
  deletedDependencies: Array<string> = []
) => {
  for (let i = 0; i < instances.length; i += 1) {
    const instance = instances[i];
    for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
      const rule = rules[ruleIndex];
      const isElementCleanable = isNotEmptyField(instance[`${RULE_PREFIX}${rule.id}`]);
      if (isElementCleanable) {
        const processingElement: StoreObject = await storeLoadByIdWithRefs(context, RULE_MANAGER_USER, instance.internal_id);
        // In case of "inference of inference", element can be recursively cleanup by the deletion system
        if (processingElement) {
          await rule.clean(processingElement, deletedDependencies);
        }
      }
    }
  }
};

const ruleStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>, lastEventId: string) => {
  const context = executionContext('rule_manager', RULE_MANAGER_USER);
  // Create list of events to process
  // Events must be in a compatible version and not inferences events
  // Inferences directly handle recursively by the manager
  const compatibleEvents = streamEvents.filter((event) => {
    const eventVersion = parseInt(event.data?.version ?? '0', 10);
    return eventVersion >= MIN_LIVE_STREAM_EVENT_VERSION;
  });
  if (compatibleEvents.length > 0) {
    const ruleEvents: Array<BaseEvent> = compatibleEvents.map((e) => e.data);
    // Execute the events
    await rulesApplyHandler(context, RULE_MANAGER_USER, ruleEvents);
  }
  // Save the last processed event
  logApp.debug(`[OPENCTI] Rule manager saving state to ${lastEventId}`);
  await patchAttribute(context, RULE_MANAGER_USER, RULE_ENGINE_ID, ENTITY_TYPE_RULE_MANAGER, { lastEventId });
};

const getInitRuleManager = async (): Promise<BasicStoreEntity> => {
  const context = executionContext('rule_manager', RULE_MANAGER_USER);
  const ruleSettingsInput = { internal_id: RULE_ENGINE_ID, errors: [] };
  const created = await createEntity(context, RULE_MANAGER_USER, ruleSettingsInput, ENTITY_TYPE_RULE_MANAGER);
  return created as BasicStoreEntity;
};

const initRuleManager = () => {
  const WAIT_TIME_ACTION = 2000;
  let scheduler: SetIntervalAsyncTimer<[]>;
  let streamProcessor: StreamProcessor;
  let syncListening = true;
  let running = false;
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
      running = true;
      logApp.info(`[OPENCTI-MODULE] Running rule manager from ${lastEventId ?? 'start'}`);
      // Start the stream listening
      const opts = { withInternal: true, streamName: REDIS_STREAM_NAME };
      streamProcessor = createStreamProcessor(RULE_MANAGER_USER, 'Rule manager', ruleStreamHandler, opts);
      await streamProcessor.start(lastEventId);
      while (syncListening) {
        await wait(WAIT_TIME_ACTION);
      }
    } catch (e: any) {
      if (e.name === TYPE_LOCK_ERROR) {
        logApp.info('[OPENCTI-MODULE] Rule engine already started by another API');
      } else {
        logApp.error('[OPENCTI-MODULE] Rule engine failed to start', { error: e });
      }
    } finally {
      running = false;
      if (streamProcessor) await streamProcessor.shutdown();
      if (lock) await lock.unlock();
    }
  };
  return {
    start: async () => {
      const ruleManager = await getInitRuleManager();
      scheduler = setIntervalAsync(async () => {
        await ruleHandler(ruleManager.lastEventId);
      }, SCHEDULE_TIME);
    },
    status: () => {
      return {
        id: 'RULE_ENGINE',
        enable: booleanConf('rule_engine:enabled', false),
        running,
      };
    },
    shutdown: async () => {
      syncListening = false;
      if (scheduler) {
        return clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};
const ruleEngine = initRuleManager();

export const cleanRuleManager = async (context: AuthContext, user: AuthUser, eventId: string) => {
  // Clear the elastic status
  const patch = { lastEventId: eventId, errors: [] };
  const { element } = await patchAttribute(context, user, RULE_ENGINE_ID, ENTITY_TYPE_RULE_MANAGER, patch);
  // Restart the manager
  await ruleEngine.shutdown();
  await ruleEngine.start();
  // Return the updated element
  return { activated: ENABLED_RULE_ENGINE, ...element };
};

export default ruleEngine;
