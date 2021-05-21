import { createStreamProcessor, lockResource } from '../database/redis';
import { SYSTEM_USER } from '../utils/access';
import conf from '../config/conf';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { RELATION_ATTRIBUTED_TO } from '../schema/stixCoreRelationship';
import {
  buildRelationTimeFilter,
  createInferredRelation,
  deleteInferredElement,
  listAllRelations,
} from '../database/middleware';
import { INDEX_MARKINGS_FIELD } from '../schema/general';
import { READ_DATA_INDICES } from '../database/utils';
import { elList } from '../database/elasticSearch';

const INFERENCE_ENGINE_KEY = conf.get('inference_engine:lock_key');
/*
AttributionAttributionRule: 'This rule can be used to infer the following fact: if an
entity A is attributed to an entity B and the entity B is attributed to an entity C, the
entity A is also attributed to the entity C.'
 */
const AttributionRule = 'rule_attribution';
const rules = [AttributionRule];

const rulesHandler = {
  [AttributionRule]: async (topic, data) => {
    const events = [];
    // If action directly related to the relation
    const relationType = RELATION_ATTRIBUTED_TO;
    if (data.relationship_type === relationType) {
      const { x_opencti_id: createdId, object_marking_refs: markingIds } = data;
      const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
      if (topic === EVENT_TYPE_CREATE || topic === EVENT_TYPE_UPDATE) {
        const timeFilters = buildRelationTimeFilter(data);
        // Need to discover on the from and the to if attributed-to also exists
        // IN CREATION: (A) -> attributed-to -> (B)
        // (P) -> FIND_RELS (attributed-to) -> (A) -> attributed-to -> (B)
        // (P) -> attributed-to -> (B)
        const listFromCallback = async (relationships) => {
          for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
            const { id: foundRelationId, fromId } = relationships[sIndex];
            const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
            // We do not need to propagate the creation here.
            // Because created relation have the same type.
            const input = {
              fromId,
              toId: targetRef,
              relationship_type: relationType,
              objectMarking: [...(markingIds || []), ...(relInternalMarkings || [])],
              // start_time ?
              // end_time ?
              inferenceRule: {
                name: AttributionRule,
                explanation: [foundRelationId, createdId], // Free form, depending of the rules
                dependencies: [fromId, foundRelationId, sourceRef, createdId, targetRef], // Must contains all participants ids
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
            const { id: foundRelationId, toId } = relationships[sIndex];
            const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
            // We do not need to propagate the creation here.
            // Because created relation have the same type.
            const input = {
              fromId: sourceRef,
              toId,
              relationship_type: relationType,
              objectMarking: [...(markingIds || []), ...(relInternalMarkings || [])],
              // start_time ?
              // end_time ?
              inferenceRule: {
                name: AttributionRule,
                explanation: [createdId, foundRelationId], // Free form, depending of the rules
                dependencies: [sourceRef, createdId, toId, foundRelationId, targetRef], // Must contains all participants ids
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
    }
    // If not directly related but can be impact full
    if (topic === EVENT_TYPE_MERGE) {
      // When a merge occurred, deleted entities must delete related inferences
      // The new updated entities must be rescan to recreate possible missing inferences
      // TODO
    }
    return events;
  },
};

const inferenceHandler = async (events) => {
  const generatedEvents = [];
  // Need to remove all inferences where the current id is used in the explanation
  const deleteCallback = async (elements) => {
    const deletedEvents = await deleteInferredElement(elements);
    generatedEvents.push(...deletedEvents);
  };
  for (let index = 0; index < events.length; index += 1) {
    const { topic, data: eventData } = events[index];
    if (eventData && parseInt(eventData.version, 10) >= 2) {
      const { data } = eventData;
      // Rule evaluations
      // Every rule can react to any topic type.
      for (let ruleIndex = 0; ruleIndex < rules.length; ruleIndex += 1) {
        const rule = rules[ruleIndex];
        const newEvents = await rulesHandler[rule](topic, data);
        generatedEvents.push(...newEvents);
      }
      // Generic case of deletion
      if (topic === EVENT_TYPE_DELETE || topic === EVENT_TYPE_MERGE) {
        const ids = topic === EVENT_TYPE_DELETE ? [data.x_opencti_id] : data.sources.map((s) => s.x_opencti_id);
        const filters = [{ key: 'i_inference_rule.dependencies', values: ids }];
        const opts = { filters, callback: deleteCallback };
        await elList(SYSTEM_USER, READ_DATA_INDICES, opts);
      }
    }
  }
  if (generatedEvents.length > 0) {
    // New events generated must also be evaluated
    // New inference can be source of another inferences
    const convertedEvents = generatedEvents.map((e) => ({ topic: e.type, data: { data: e.data, version: e.version } }));
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
        await streamProcessor.start();
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
