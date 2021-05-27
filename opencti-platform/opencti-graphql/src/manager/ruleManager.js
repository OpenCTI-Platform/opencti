/* eslint-disable camelcase */
import { buildScanEvent, createStreamProcessor, lockResource } from '../database/redis';
import conf from '../config/conf';
import RuleAttributedInference from './rules/RuleAttributedInference';
import RuleRelatedInference from './rules/RuleObservableRelatedInference';
import { stixLoadById } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import RuleConfidenceLevel from './rules/RuleConfidenceLevel';
import { isEmptyField } from '../database/utils';

const RULE_ENGINE_KEY = conf.get('rule_engine:lock_key');

export const declaredRules = [RuleAttributedInference, RuleRelatedInference, RuleConfidenceLevel];

const ruleApplyHandler = async (events, cleanBefore = false) => {
  try {
    if (isEmptyField(events) || events.length === 0) return;
    if (cleanBefore) {
      for (let index = 0; index < events.length; index += 1) {
        const event = events[index];
        for (let ruleIndex = 0; ruleIndex < declaredRules.length; ruleIndex += 1) {
          const rule = declaredRules[ruleIndex];
          const derivedEvents = await rule.clean(event);
          await ruleApplyHandler(derivedEvents, cleanBefore);
        }
      }
    }
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      for (let ruleIndex = 0; ruleIndex < declaredRules.length; ruleIndex += 1) {
        const rule = declaredRules[ruleIndex];
        const derivedEvents = await rule.apply(event);
        await ruleApplyHandler(derivedEvents, cleanBefore);
      }
    }
  } catch (e) {
    console.log(e);
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
  // Execute rules over one element, act as element creation
  const event = await buildScanEvent(user, element, stixLoadById);
  await ruleApplyHandler([event], true);
};

export default initRuleManager;
