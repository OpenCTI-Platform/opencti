import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import indicatorTypeDefs from './indicator.graphql';
import indicatorResolvers from './indicator-resolver';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_INDICATOR, type StixIndicator, type StoreEntityIndicator } from './indicator-types';
import convertIndicatorToStix from './indicator-converter';

const INDICATOR_DEFINITION: ModuleDefinition<StoreEntityIndicator, StixIndicator> = {
  type: {
    id: 'indicator',
    name: ENTITY_TYPE_INDICATOR,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: true
  },
  graphql: {
    schema: indicatorTypeDefs,
    resolver: indicatorResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INDICATOR]: [{ src: NAME_FIELD }, { src: 'context' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [ // FIXME
    { name: 'name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true },
    { name: 'content', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true },
    { name: 'content_mapping', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true },
    { name: 'context', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true },
  ],
  relations: [],
  representative: (stix: StixIndicator) => {
    return stix.name;
  },
  converter: convertIndicatorToStix
};

registerDefinition(INDICATOR_DEFINITION);
