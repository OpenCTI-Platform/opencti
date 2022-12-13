import caseTypeDefs from './case.graphql';
import convertCaseToStix from './case-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import caseResolvers from './case-resolvers';
import { ENTITY_TYPE_CONTAINER_CASE, StoreEntityCase } from './case-types';

const CASE_DEFINITION: ModuleDefinition<StoreEntityCase> = {
  type: {
    id: 'cases',
    name: ENTITY_TYPE_CONTAINER_CASE,
    category: 'StixDomainEntity',
    aliased: false
  },
  graphql: {
    schema: caseTypeDefs,
    resolver: caseResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CONTAINER_CASE]: [{ src: NAME_FIELD }]
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
    { name: 'rating', type: 'numeric', multiple: false, upsert: true },
  ],
  relations: [],
  converter: convertCaseToStix
};

registerDefinition(CASE_DEFINITION);
