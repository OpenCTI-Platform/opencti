import type { StixDataSource, StoreEntityDataSource } from './dataSource-types';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import convertDataSourceToStix from './dataSource-converter';
import { ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';

const DATA_SOURCE_DEFINITION: ModuleDefinition<StoreEntityDataSource, StixDataSource> = {
  type: {
    id: 'dataSources',
    name: ENTITY_TYPE_DATA_SOURCE,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_DATA_SOURCE]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  overviewLayoutCustomization: [
    { key: 'details', width: 6, label: 'Entity details' },
    { key: 'basicInformation', width: 6, label: 'Basic information' },
    { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
    { key: 'latestContainers', width: 6, label: 'Latest containers' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', format: 'vocabulary', vocabularyCategory: 'platforms_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'collection_layers', label: 'Layers', type: 'string', format: 'vocabulary', vocabularyCategory: 'collection_layers_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [
    { ...objectOrganization, isFilterable: false }
  ],
  representative: (stix: StixDataSource) => {
    return stix.name;
  },
  converter: convertDataSourceToStix
};

registerDefinition(DATA_SOURCE_DEFINITION);
