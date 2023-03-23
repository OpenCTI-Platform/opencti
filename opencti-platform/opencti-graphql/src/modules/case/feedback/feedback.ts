import feedbackTypeDefs from './feedback.graphql';
import { ENTITY_TYPE_CONTAINER_FEEDBACK, StixFeedback, StoreEntityFeedback } from './feedback-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import feedbackResolvers from './feedback-resolvers';
import convertFeedbackToStix from './feedback-converter';
import { createdBy, objectAssignee, objectMarking } from '../../../schema/stixMetaRelationship';

const FEEDBACK_DEFINITION: ModuleDefinition<StoreEntityFeedback, StixFeedback> = {
  type: {
    id: 'feedback',
    name: ENTITY_TYPE_CONTAINER_FEEDBACK,
    category: ENTITY_TYPE_CONTAINER_CASE,
    aliased: false
  },
  graphql: {
    schema: feedbackTypeDefs,
    resolver: feedbackResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_FEEDBACK]: [{ src: NAME_FIELD }, { src: 'created' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'rating', type: 'numeric', mandatoryType: 'external', multiple: false, upsert: true },
  ],
  relations: [],
  relationsRefs: [createdBy, objectMarking, objectAssignee],
  representative: (stix: StixFeedback) => {
    return stix.name;
  },
  converter: convertFeedbackToStix
};

registerDefinition(FEEDBACK_DEFINITION);
