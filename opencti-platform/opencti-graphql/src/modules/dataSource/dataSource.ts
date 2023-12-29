import dataSourceTypeDefs from './dataSource.graphql';
import type { StixDataSource, StoreEntityDataSource } from './dataSource-types';
import dataSourceResolvers from './dataSource-resolvers';
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
    aliased: true
  },
  graphql: {
    schema: dataSourceTypeDefs,
    resolver: dataSourceResolvers,
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
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'collection_layers', label: 'Layers', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [
    objectOrganization
  ],
  representative: (stix: StixDataSource) => {
    return stix.name;
  },
  converter: convertDataSourceToStix
};

registerDefinition(DATA_SOURCE_DEFINITION);
