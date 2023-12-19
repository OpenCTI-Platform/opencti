import narrativeTypeDefs from './narrative.graphql';
import convertNarrativeToStix from './narrative-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import narrativeResolvers from './narrative-resolver';
import { ENTITY_TYPE_NARRATIVE, type StixNarrative, type StoreEntityNarrative } from './narrative-types';
import { REL_NEW } from '../../database/stix';
import { RELATION_SUBNARRATIVE_OF } from '../../schema/stixCoreRelationship';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';

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
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'narrative_types', label: 'Narrative types', type: 'string', mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
  ],
  relations: [
    {
      name: RELATION_SUBNARRATIVE_OF,
      targets: [
        { name: ENTITY_TYPE_NARRATIVE, type: REL_NEW },
      ]
    },
  ],
  relationsRefs: [
    objectOrganization
  ],
  representative: (stix: StixNarrative) => {
    return stix.name;
  },
  converter: convertNarrativeToStix
};

registerDefinition(NARRATIVE_DEFINITION);
