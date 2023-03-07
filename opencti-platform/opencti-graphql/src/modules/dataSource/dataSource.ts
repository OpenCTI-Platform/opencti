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
    { name: 'name', type: 'string', mandatoryType: 'external', multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', multiple: false, upsert: true },
    { name: 'x_mitre_platforms', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'Platforms' },
    { name: 'collection_layers', type: 'string', mandatoryType: 'customizable', multiple: true, upsert: true, label: 'Layers' },
    { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: true },
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
