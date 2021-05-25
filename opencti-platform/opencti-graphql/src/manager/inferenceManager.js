/* eslint-disable camelcase */
import { createStreamProcessor, lockResource } from '../database/redis';
import { SYSTEM_USER } from '../utils/access';
import conf from '../config/conf';
import { EVENT_TYPE_DELETE, EVENT_TYPE_MERGE } from '../database/rabbitmq';
import { deleteInferredElement } from '../database/middleware';
import { READ_DATA_INDICES } from '../database/utils';
import { elList } from '../database/elasticSearch';
import AttributionRule from '../inference/AttributionRule';
import RelatedRule from '../inference/RelatedRule';

const INFERENCE_ENGINE_KEY = conf.get('inference_engine:lock_key');

const registerInferenceRules = [AttributionRule, RelatedRule];

const executeInternalEvents = async (internalEvents) => {
  if (internalEvents.length === 0) return;
  const eventBuilder = (e) => ({ topic: e.type, data: { data: e.data, version: e.version } });
  const convertedEvents = internalEvents.map((e) => eventBuilder(e));
  // eslint-disable-next-line no-use-before-define
  await inferenceHandler(convertedEvents);
};

const executeInferenceDefaultBehavior = async (topic, data) => {
  // Generic case of deletion
  // When merging, simpler to delete everything and the recreate inferences
  if (topic === EVENT_TYPE_DELETE || topic === EVENT_TYPE_MERGE) {
    const ids = [];
    if (topic === EVENT_TYPE_DELETE) {
      ids.push(data.x_opencti_id);
    }
    if (topic === EVENT_TYPE_MERGE) {
      ids.push(...data.sources.map((s) => s.x_opencti_id));
    }
    const filters = [{ key: 'i_inference_rule.dependencies', values: ids }];
    const deleteCallback = async (elements) => {
      const deletedEvents = await deleteInferredElement(elements);
      // If new events derived from the event, execute them
      await executeInternalEvents(deletedEvents);
    };
    const opts = { filters, callback: deleteCallback };
    await elList(SYSTEM_USER, READ_DATA_INDICES, opts);
  }
};

const inferenceHandler = async (events) => {
  // const generatedEvents = [];
  // Need to remove all inferences where the current id is used in the explanation
  for (let index = 0; index < events.length; index += 1) {
    const { topic, data: eventData } = events[index];
    if (eventData && parseInt(eventData.version, 10) >= 2) {
      const { data, markings } = eventData;
      // Rule evaluations - Every rule can react to any topic type.
      for (let ruleIndex = 0; ruleIndex < registerInferenceRules.length; ruleIndex += 1) {
        const rule = registerInferenceRules[ruleIndex];
        const newEvents = await rule.apply(topic, markings, data);
        // If new events derived from the event, execute them
        await executeInternalEvents(newEvents);
      }
      // Execute default behavior
      await executeInferenceDefaultBehavior(topic, data);
    }
  }
};

const initInferenceManager = () => {
  let streamProcessor;
  return {
    start: async () => {
      let lock;
      try {
        // Lock the manager
        lock = await lockResource([INFERENCE_ENGINE_KEY]);
        streamProcessor = await createStreamProcessor(SYSTEM_USER, inferenceHandler);
        await streamProcessor.start();
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

export default initInferenceManager;
