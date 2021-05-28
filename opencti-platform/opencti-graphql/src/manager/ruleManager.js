/* eslint-disable camelcase */
import * as R from 'ramda';
import { buildDeleteEvent, buildScanEvent, createStreamProcessor, lockResource } from '../database/redis';
import conf, { logApp } from '../config/conf';
import RuleAttributedInference from './rules/RuleAttributedInference';
import RuleObservableRelatedObservable from './rules/RuleObservableRelatedInference';
import { listAllRelations, stixLoadById } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import RuleConfidenceLevel from './rules/RuleConfidenceLevel';
import { isEmptyField, READ_DATA_INDICES } from '../database/utils';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { elList } from '../database/elasticSearch';
import { STIX_RELATIONSHIPS } from '../schema/stixRelationship';
import { RULE_PREFIX } from '../schema/general';
import RuleRelatedInference from './rules/RuleRelatedInference';

const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');

export const declaredRules = [
  RuleAttributedInference,
  RuleObservableRelatedObservable,
  RuleConfidenceLevel,
  RuleRelatedInference,
];
export const getRule = (name) => R.find((e) => e.name === name)(declaredRules);

const activatedRules = declaredRules;

const ruleMergeHandler = async (event) => {
  const { data } = event;
  // Need to generate events for deletion
  const events = data.sources.map((s) => buildDeleteEvent(SYSTEM_USER, s, stixLoadById));
  // Need to generate event for redo rule on updated element
  const mergeCallback = async (relationships) => {
    const creationEvents = relationships.map((r) => buildScanEvent(SYSTEM_USER, r, stixLoadById));
    events.push(...creationEvents);
  };
  const listToArgs = { elementId: data.x_opencti_id, callback: mergeCallback };
  await listAllRelations(SYSTEM_USER, STIX_RELATIONSHIPS, listToArgs);
  return events;
};

const ruleApplyHandler = async (events) => {
  if (isEmptyField(events) || events.length === 0) return;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    try {
      const { type, data, markings } = event;
      const element = { ...data, object_marking_refs: markings };
      // In case of merge convert the events to basic events and restart the process
      if (type === EVENT_TYPE_MERGE) {
        const derivedEvents = await ruleMergeHandler(event);
        await ruleApplyHandler(derivedEvents);
      }
      // In case of deletion, call clean on every impacted elements
      if (type === EVENT_TYPE_DELETE) {
        const filters = [{ key: `${RULE_PREFIX}*.dependencies`, values: [data.x_opencti_id], operator: 'wildcard' }];
        // eslint-disable-next-line no-use-before-define
        const opts = { filters, callback: handleRuleDeleteElements };
        await elList(SYSTEM_USER, READ_DATA_INDICES, opts);
      }
      // In case of update apply the event on every rules
      if (type === EVENT_TYPE_UPDATE) {
        for (let ruleIndex = 0; ruleIndex < activatedRules.length; ruleIndex += 1) {
          const rule = activatedRules[ruleIndex];
          const derivedEvents = await rule.update(element);
          await ruleApplyHandler(derivedEvents);
        }
      }
      // In case of creation apply the event on every rules
      if (type === EVENT_TYPE_CREATE) {
        for (let ruleIndex = 0; ruleIndex < activatedRules.length; ruleIndex += 1) {
          const rule = activatedRules[ruleIndex];
          const derivedEvents = await rule.insert(element);
          await ruleApplyHandler(derivedEvents);
        }
      }
    } catch (e) {
      logApp.error('Error in rule processing', { event });
    }
  }
};

export const handleRuleDeleteElements = async (depElements) => {
  for (let i = 0; i < depElements.length; i += 1) {
    const depElement = depElements[i];
    const elementRules = Object.keys(depElement)
      .filter((k) => k.startsWith(RULE_PREFIX))
      .map((k) => k.substr(RULE_PREFIX.length));
    const rulesToClean = activatedRules.filter((d) => elementRules.includes(d.name));
    for (let ruleIndex = 0; ruleIndex < rulesToClean.length; ruleIndex += 1) {
      const rule = rulesToClean[ruleIndex];
      const derivedEvents = await rule.clean(depElement);
      await ruleApplyHandler(derivedEvents);
    }
  }
};

const ruleStreamHandler = async (streamEvents) => {
  const events = streamEvents
    .filter((event) => {
      const { data } = event;
      return data && parseInt(data.version, 10) >= 2;
    })
    .map((e) => {
      const { topic, data: eventData } = e;
      const { data, markings } = eventData;
      return { type: topic, markings, data };
    });
  await ruleApplyHandler(events);
};

const initRuleManager = () => {
  let streamProcessor;
  return {
    start: async () => {
      let lock;
      try {
        // Lock the manager
        lock = await lockResource([RULE_ENGINE_KEY]);
        streamProcessor = await createStreamProcessor(SYSTEM_USER, ruleStreamHandler);
        await streamProcessor.start();
        return true;
      } catch {
        return false;
      } finally {
        if (lock) await lock.unlock();
      }
    },
    shutdown: async () => {
      if (streamProcessor) {
        await streamProcessor.shutdown();
      }
      return true;
    },
  };
};

export const reapplyRules = async (user, element) => {
  await handleRuleDeleteElements([element]);
  // Execute rules over one element, act as element creation
  const event = await buildScanEvent(user, element, stixLoadById);
  await ruleApplyHandler([event]);
};

export default initRuleManager;
