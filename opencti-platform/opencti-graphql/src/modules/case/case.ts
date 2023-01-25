import caseTypeDefs from './case.graphql';
import convertCaseToStix from './case-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import caseResolvers from './case-resolvers';
import { ENTITY_TYPE_CONTAINER_CASE, StixCase, StoreEntityCase } from './case-types';
import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';

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
      [ENTITY_TYPE_CONTAINER_CASE]: [{ src: NAME_FIELD }, { src: 'case_type' }, { src: 'created' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'case_type', type: 'string', mandatoryType: 'internal', multiple: false, upsert: true },
    { name: 'severity', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'priority', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'rating', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: true },
    { name: 'confidence', type: 'numeric', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixCase) => {
    return stix.name;
  },
  converter: convertCaseToStix
};

registerDefinition(CASE_DEFINITION);
