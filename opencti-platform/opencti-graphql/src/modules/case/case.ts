import { ENTITY_TYPE_CONTAINER } from '../../schema/general';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import convertCaseToStix from './case-converter';
import caseResolvers from './case-resolvers';
import { ENTITY_TYPE_CONTAINER_CASE, StixCase, StoreEntityCase } from './case-types';
import caseTypeDefs from './case.graphql';

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
    { name: 'caseTemplate', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
  ],
  relations: [],
  relationsRefs: [objectOrganization],
  representative: (stix: StixCase) => {
    return stix.name;
  },
  converter: convertCaseToStix
};

registerDefinition(CASE_DEFINITION);
