import dataComponentTypeDefs from './dataComponent.graphql';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_DATA_COMPONENT,
  ENTITY_TYPE_DATA_SOURCE
} from '../../schema/stixDomainObject';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type { StixDataComponent, StoreEntityDataComponent } from './dataComponent-types';
import { INPUT_DATA_SOURCE } from './dataComponent-types';
import dataComponentResolvers from './dataComponent-resolver';
import convertDataComponentToStix from './dataComponent-converter';
import { RELATION_DETECTS } from '../../schema/stixCoreRelationship';
import { REL_EXTENDED } from '../../database/stix';
import { ATTRIBUTE_DATA_SOURCE, RELATION_DATA_SOURCE } from './dataComponent-domain';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';

const DATA_COMPONENT_DEFINITION: ModuleDefinition<StoreEntityDataComponent, StixDataComponent> = {
  type: {
    id: 'dataComponents',
    name: ENTITY_TYPE_DATA_COMPONENT,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: true
  },
  graphql: {
    schema: dataComponentTypeDefs,
    resolver: dataComponentResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DATA_COMPONENT]: [{ src: NAME_FIELD }]
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
    { name: 'x_opencti_workflow_id', type: 'string', multiple: false, upsert: true },
  ],
  relations: [
    {
      name: RELATION_DETECTS,
      targets: [
        {
          name: ENTITY_TYPE_ATTACK_PATTERN,
          type: REL_EXTENDED
        }
      ]
    }
  ],
  relationsRefs: [
    {
      attribute: ATTRIBUTE_DATA_SOURCE,
      input: INPUT_DATA_SOURCE,
      relation: RELATION_DATA_SOURCE,
      multiple: false,
      checker: (fromType, toType) => toType === ENTITY_TYPE_DATA_SOURCE
    }
  ],
  representative: (stix: StixDataComponent) => {
    return stix.name;
  },
  converter: convertDataComponentToStix
};

registerDefinition(DATA_COMPONENT_DEFINITION);
