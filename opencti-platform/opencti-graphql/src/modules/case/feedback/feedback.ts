import feedbackTypeDefs from './feedback.graphql';
import { ENTITY_TYPE_CONTAINER_FEEDBACK, type StixFeedback, type StoreEntityFeedback } from './feedback-types';
import { ENTITY_TYPE_CONTAINER_CASE } from '../case-types';
import { NAME_FIELD, normalizeName } from '../../../schema/identifier';
import type { ModuleDefinition } from '../../../schema/module';
import { registerDefinition } from '../../../schema/module';
import feedbackResolvers from './feedback-resolvers';
import convertFeedbackToStix from './feedback-converter';
import { createdBy, objectAssignee, objectMarking } from '../../../schema/stixRefRelationship';
import { authorizedMembers } from '../../../schema/attribute-definition';

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
    { name: 'rating', label: 'Rating', type: 'numeric', precision: 'integer', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    authorizedMembers
  ],
  relations: [],
  relationsRefs: [
    { ...createdBy, mandatoryType: 'no' },
    { ...objectMarking, mandatoryType: 'no' },
    { ...objectAssignee, mandatoryType: 'no' },
  ],
  representative: (stix: StixFeedback) => {
    return stix.name;
  },
  converter: convertFeedbackToStix
};

registerDefinition(FEEDBACK_DEFINITION);
