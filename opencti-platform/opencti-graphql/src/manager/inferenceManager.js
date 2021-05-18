import { createStreamProcessor, lockResource } from '../database/redis';
import { SYSTEM_USER } from '../utils/access';
import conf from '../config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { RELATION_ATTRIBUTED_TO, RELATION_RELATED_TO } from '../schema/stixCoreRelationship';
import { buildRelationTimeFilter, createInferredRelation, listAllRelations } from '../database/middleware';
import { INDEX_MARKINGS_FIELD } from '../schema/general';

const INFERENCE_ENGINE_KEY = conf.get('inference_engine:lock_key');
/*
AttributionAttributionRule: 'This rule can be used to infer the following fact: if an
entity A is attributed to an entity B and the entity B is attributed to an entity C, the
entity A is also attributed to the entity C.'
 */
const rules = ['AttributionAttributionRule'];

const rulesHandler = {
  AttributionAttributionRule: async (topic, data) => {
    const events = [];
    const relationType = RELATION_RELATED_TO;
    if (data?.relationship_type !== relationType) {
      return events;
    }
    const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef, object_marking_refs: markingIds } = data;
    if (topic === EVENT_TYPE_CREATE) {
      const timeFilters = buildRelationTimeFilter(data);
      // Need to discover on the from and the to if attributed-to also exists
      // (A) -> attributed-to -> (B)
      // (P) -> FIND_RELS -> (A) -> attributed-to -> (B)
      // (P) -> attributed-to -> (B)
      const listFromCallback = async (relationships) => {
        for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
          const { fromId } = relationships[sIndex];
          const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
          // We do not need to propagate the creation here.
          // Because created relation have the same type.
          const input = {
            fromId,
            toId: targetRef,
            relationship_type: relationType,
            objectMarking: [...(markingIds || []), ...(relInternalMarkings || [])],
            explanation: {
              ids: [sourceRef, targetRef],
              type: relationType,
              rule: 'AttributionAttributionRule',
            },
          };
          const event = await createInferredRelation(input);
          if (event) {
            events.push(event);
          }
        }
      };
      const listFromArgs = { toId: sourceRef, callback: listFromCallback, ...timeFilters };
      await listAllRelations(SYSTEM_USER, relationType, listFromArgs);
      // Need to discover on the from and the to if attributed-to also exists
      // (A) -> attributed-to -> (B)
      // (A) -> attributed-to -> (B) -> FIND_RELS -> (P)
      // (A) -> attributed-to -> (P)
      const listToCallback = async (relationships) => {
        for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
          const { toId } = relationships[sIndex];
          const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
          // We do not need to propagate the creation here.
          // Because created relation have the same type.
          const input = {
            fromId: sourceRef,
            toId,
            relationship_type: relationType,
            objectMarking: [...(markingIds || []), ...(relInternalMarkings || [])],
            explanation: {
              ids: [sourceRef, targetRef],
              type: relationType,
              rule: 'AttributionAttributionRule',
            },
          };
          const event = await createInferredRelation(input);
          if (event) {
            events.push(event);
          }
        }
      };
      const listToArgs = { fromId: targetRef, callback: listToCallback, ...timeFilters };
      await listAllRelations(SYSTEM_USER, relationType, listToArgs);
    }
    if (topic === EVENT_TYPE_UPDATE) {
      // Depending of the update inference could be created or deleted
      // TODO Rules?
    }
    if (topic === EVENT_TYPE_DELETE) {
      // Need to remove all inferences where the current id is used in the explanation
    }
    return events;
  },
};

const inferenceHandler = async (events) => {
  const generatedEvents = [];
  for (let index = 0; index < events.length; index += 1) {
    const { topic, data: eventData } = events[index];
    const { data } = eventData;
    for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
      const rule = rules[ruleIndex];
      const newEvents = await rulesHandler[rule](topic, data);
      generatedEvents.push(...newEvents);
    }
  }
  if (generatedEvents.length > 0) {
    // New events generated must also be evaluated
    // New inference can be source of another inferences
    const convertedEvents = generatedEvents.map((e) => ({ topic: e.type, data: { data: e.data } }));
    await inferenceHandler(convertedEvents);
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
        await streamProcessor.start('1621364986480');
        return true;
      } catch (e) {
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

export default initInferenceManager;
