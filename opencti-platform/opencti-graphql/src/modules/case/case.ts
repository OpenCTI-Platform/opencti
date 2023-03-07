import caseTypeDefs from './case.graphql';
import convertCaseToStix from './case-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import caseResolvers from './case-resolvers';
import { ENTITY_TYPE_CONTAINER_CASE, StixCase, StoreEntityCase } from './case-types';
import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { createdBy, objectAssignee, objectMarking, objectOrganization } from '../../schema/stixRefRelationship';

const CASE_DEFINITION: ModuleDefinition<StoreEntityCase, StixCase> = {
  type: {
    id: 'cases',
    name: ENTITY_TYPE_CONTAINER_CASE,
    category: ENTITY_TYPE_CONTAINER,
    aliased: false
  },
  graphql: {
    schema: caseTypeDefs,
    resolver: caseResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE]: [{ src: NAME_FIELD }, { src: 'created' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],

  relationsRefs: [ // Case cant use standard mandatory attributes, waiting a split from feedbacks
    { ...createdBy, mandatoryType: 'no' },
    { ...objectMarking, mandatoryType: 'no' },
    { ...objectAssignee, mandatoryType: 'no' },
    objectOrganization
  ],
  representative: (stix: StixCase) => {
    return stix.name;
  },
  converter: convertCaseToStix
};

registerDefinition(CASE_DEFINITION);
