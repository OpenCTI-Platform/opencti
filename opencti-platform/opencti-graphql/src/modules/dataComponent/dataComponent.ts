import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_DATA_COMPONENT, ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ATTRIBUTE_DATA_SOURCE, RELATION_DATA_SOURCE, type StixDataComponent, type StoreEntityDataComponent } from './dataComponent-types';
import { INPUT_DATA_SOURCE } from './dataComponent-types';
import convertDataComponentToStix from './dataComponent-converter';
import { RELATION_DETECTS } from '../../schema/stixCoreRelationship';
import { REL_EXTENDED } from '../../database/stix';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';

const DATA_COMPONENT_DEFINITION: ModuleDefinition<StoreEntityDataComponent, StixDataComponent> = {
  type: {
    id: 'dataComponents',
    name: ENTITY_TYPE_DATA_COMPONENT,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: true
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
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
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
      name: INPUT_DATA_SOURCE,
      type: 'ref',
      databaseName: RELATION_DATA_SOURCE,
      stixName: ATTRIBUTE_DATA_SOURCE,
      label: 'Data source',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      checker: (fromType, toType) => toType === ENTITY_TYPE_DATA_SOURCE,
      isFilterable: true,
    },
    objectOrganization
  ],
  representative: (stix: StixDataComponent) => {
    return stix.name;
  },
  converter: convertDataComponentToStix
};

registerDefinition(DATA_COMPONENT_DEFINITION);
