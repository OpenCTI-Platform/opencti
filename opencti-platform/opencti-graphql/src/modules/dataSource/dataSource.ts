import dataSourceTypeDefs from './dataSource.graphql';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import type { StixDataSource, StoreEntityDataSource } from './dataSource-types';
import dataSourceResolvers from './dataSource-resolvers';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import convertDataSourceToStix from './dataSource-converter';
import { ENTITY_TYPE_DATA_SOURCE } from '../../schema/stixDomainObject';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';

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
    { name: 'name', type: 'string', multiple: false, upsert: true },
    { name: 'description', type: 'string', multiple: false, upsert: true },
    { name: 'x_mitre_platforms', type: 'string', multiple: true, upsert: true },
    { name: 'collection_layers', type: 'string', multiple: true, upsert: true },
    { name: 'dataComponents', type: 'string', multiple: true, upsert: true },
    { name: 'x_opencti_workflow_id', type: 'string', multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixDataSource) => {
    return stix.name;
  },
  converter: convertDataSourceToStix
};

registerDefinition(DATA_SOURCE_DEFINITION);
