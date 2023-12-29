import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import indicatorTypeDefs from './indicator.graphql';
import indicatorResolvers from './indicator-resolver';
import { ENTITY_TYPE_INDICATOR, type StixIndicator, type StoreEntityIndicator } from './indicator-types';
import convertIndicatorToStix from './indicator-converter';
import { killChainPhases, objectOrganization } from '../../schema/stixRefRelationship';

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
      [ENTITY_TYPE_INDICATOR]: [{ src: 'pattern' }]
    },
    resolvers: {},
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'pattern_type', label: 'Pattern type', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'pattern_version', label: 'Pattern version', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'pattern', label: 'Pattern', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'indicator_types', label: 'Indicator types', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'valid_from', label: 'Valid from', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'valid_until', label: 'Valid until', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_score', label: 'Score', type: 'numeric', precision: 'integer', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_detection', label: 'Detection', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_main_observable_type', label: 'Main observable type', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [objectOrganization, killChainPhases],
  representative: (stix: StixIndicator) => {
    return stix.name;
  },
  converter: convertIndicatorToStix
};

registerDefinition(INDICATOR_DEFINITION);
