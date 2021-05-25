/* eslint-disable camelcase */
import { EVENT_TYPE_CREATE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/rabbitmq';
import { buildPeriodFromDates, computeRangeIntersection } from '../utils/format';
import { INDEX_MARKINGS_FIELD } from '../schema/general';
import { createInferredRelation, listAllRelations, stixLoadById } from '../database/middleware';
import { SYSTEM_USER } from '../utils/access';
import { buildCreateEvent } from '../database/redis';

/*
AttributionAttributionRule: 'This rule can be used to infer the following fact: if an
entity A is attributed to an entity B and the entity B is attributed to an entity C, the
entity A is also attributed to the entity C.'
 */
const buildRelationToRelationRule = (name, relationType) => {
  return {
    name,
    apply: async (topic, markings, data) => {
      const events = [];
      // If action directly related to the relation
      const isImpactedTopic = topic === EVENT_TYPE_CREATE || topic === EVENT_TYPE_UPDATE;
      const isImpactedRelation = data.relationship_type === relationType;
      // In case of relation creation or update
      if (isImpactedRelation && isImpactedTopic) {
        const { x_opencti_id: createdId } = data;
        const { x_opencti_source_ref: sourceRef, x_opencti_target_ref: targetRef } = data;
        const { confidence: createdConfidence, start_time: startTime, stop_time: stopTime } = data;
        const creationRange = buildPeriodFromDates(startTime, stopTime);
        // Need to discover on the from and the to if attributed-to also exists
        // IN CREATION: (A) -> attributed-to -> (B)
        // (P) -> FIND_RELS (attributed-to) -> (A) -> attributed-to -> (B)
        // (P) -> attributed-to -> (B)
        const listFromCallback = async (relationships) => {
          for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
            const { id: foundRelationId, fromId, confidence, start_time, stop_time } = relationships[sIndex];
            const existingRange = buildPeriodFromDates(start_time, stop_time);
            const range = computeRangeIntersection(creationRange, existingRange);
            const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
            // We do not need to propagate the creation here.
            // Because created relation have the same type.
            const input = {
              fromId,
              toId: targetRef,
              relationship_type: relationType,
              objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
              confidence: createdConfidence < confidence ? createdConfidence : confidence,
              start_time: range.start,
              stop_time: range.end,
              inferenceRule: {
                name,
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
        const listFromArgs = { toId: sourceRef, callback: listFromCallback };
        await listAllRelations(SYSTEM_USER, relationType, listFromArgs);
        // Need to discover on the from and the to if attributed-to also exists
        // (A) -> attributed-to -> (B)
        // (A) -> attributed-to -> (B) -> FIND_RELS -> (P)
        // (A) -> attributed-to -> (P)
        const listToCallback = async (relationships) => {
          for (let sIndex = 0; sIndex < relationships.length; sIndex += 1) {
            const { id: foundRelationId, confidence, toId, start_time, stop_time } = relationships[sIndex];
            const existingRange = buildPeriodFromDates(start_time, stop_time);
            const range = computeRangeIntersection(creationRange, existingRange);
            const relInternalMarkings = relationships[sIndex][INDEX_MARKINGS_FIELD];
            // We do not need to propagate the creation here.
            // Because created relation have the same type.
            const input = {
              fromId: sourceRef,
              toId,
              relationship_type: relationType,
              objectMarking: [...(markings || []), ...(relInternalMarkings || [])],
              confidence: createdConfidence < confidence ? createdConfidence : confidence,
              start_time: range.start,
              stop_time: range.end,
              inferenceRule: {
                name,
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
        const listToArgs = { fromId: targetRef, callback: listToCallback };
        await listAllRelations(SYSTEM_USER, relationType, listToArgs);
      }
      // In case of merge, internal push of creation event to force recreation of the inferences
      if (topic === EVENT_TYPE_MERGE) {
        const mergeCallback = async (relationships) => {
          const creationEvents = relationships.map((r) => buildCreateEvent(SYSTEM_USER, r, {}, stixLoadById));
          events.push(...creationEvents);
        };
        const listToArgs = { elementId: data.x_opencti_id, callback: mergeCallback };
        await listAllRelations(SYSTEM_USER, relationType, listToArgs);
      }
      return events;
    },
  };
};

export default buildRelationToRelationRule;
