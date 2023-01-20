import caseTypeDefs from './case.graphql';
import convertCaseToStix from './case-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import caseResolvers from './case-resolvers';
import { ENTITY_TYPE_CONTAINER_CASE, StixCase, StoreEntityCase } from './case-types';
import { ENTITY_TYPE_CONTAINER } from '../../schema/general';

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
    { name: 'name', type: 'string', multiple: false, upsert: true },
    { name: 'description', type: 'string', multiple: false, upsert: true },
    { name: 'case_type', type: 'string', multiple: false, upsert: true },
    { name: 'severity', type: 'string', multiple: false, upsert: true },
    { name: 'priority', type: 'string', multiple: false, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', multiple: false, upsert: true },
    { name: 'rating', type: 'numeric', multiple: false, upsert: true },
    { name: 'x_opencti_stix_ids', type: 'string', multiple: true, upsert: true },
    { name: 'confidence', type: 'numeric', multiple: false, upsert: true },
    { name: 'x_opencti_graph_data', type: 'string', multiple: false, upsert: false },
  ],
  relations: [],
  representative: (stix: StixCase) => {
    return stix.name;
  },
  converter: convertCaseToStix
};

registerDefinition(CASE_DEFINITION);
