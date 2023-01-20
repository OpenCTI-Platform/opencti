import narrativeTypeDefs from './narrative.graphql';
import convertNarrativeToStix from './narrative-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import narrativeResolvers from './narrative-resolver';
import { ENTITY_TYPE_NARRATIVE, StixNarrative, StoreEntityNarrative } from './narrative-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { REL_NEW } from '../../database/stix';
import { RELATION_SUBNARRATIVE_OF } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';

const NARRATIVE_DEFINITION: ModuleDefinition<StoreEntityNarrative, StixNarrative> = {
  type: {
    id: 'narratives',
    name: ENTITY_TYPE_NARRATIVE,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
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
    { name: 'x_opencti_workflow_id', type: 'string', multiple: false, upsert: true },
  ],
  relations: [
    { name: RELATION_SUBNARRATIVE_OF,
      targets: [
        { name: ENTITY_TYPE_NARRATIVE, type: REL_NEW },
      ] },
  ],
  representative: (stix: StixNarrative) => {
    return stix.name;
  },
  converter: convertNarrativeToStix
};

registerDefinition(NARRATIVE_DEFINITION);
