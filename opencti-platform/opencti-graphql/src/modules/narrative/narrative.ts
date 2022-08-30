import narrativeTypeDefs from './narrative.graphql';
import convertNarrativeToStix from './narrative-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import narrativeResolvers from './narrative-resolver';
import { ENTITY_TYPE_NARRATIVE, RELATION_SUBNARRATIVE_OF, StoreEntityNarrative } from './narrative-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { REL_NEW } from '../../database/stix';

const NARRATIVE_DEFINITION: ModuleDefinition<StoreEntityNarrative> = {
  type: {
    id: 'narratives',
    name: ENTITY_TYPE_NARRATIVE,
    category: 'StixDomainEntity',
    aliased: true
  },
  graphql: {
    schema: narrativeTypeDefs,
    resolver: narrativeResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_NARRATIVE]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', multiple: false, upsert: true },
    { name: 'narrative_types', type: 'string', multiple: true, upsert: true },
    { name: 'description', type: 'string', multiple: false, upsert: true },
  ],
  relations: [
    { name: RELATION_SUBNARRATIVE_OF,
      targets: [
        { name: ENTITY_TYPE_NARRATIVE, type: REL_NEW },
      ] },
  ],
  converter: convertNarrativeToStix
};

registerDefinition(NARRATIVE_DEFINITION);
