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
  attributes: [
    { name: 'name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true },
    { name: 'description', type: 'string', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true },
    {
      name: 'pattern_type',
      type: 'string',
      mandatoryType: 'external',
      editDefault: true,
      multiple: false,
      upsert: false,
      label: 'Pattern type'
    },
    { name: 'pattern_version', type: 'string', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, label: 'Pattern version' },
    { name: 'pattern', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false },
    {
      name: 'indicator_types',
      type: 'string',
      mandatoryType: 'customizable',
      editDefault: true,
      multiple: true,
      upsert: true,
      label: 'Indicator types'
    },
    {
      name: 'valid_from',
      type: 'date',
      mandatoryType: 'customizable',
      editDefault: true,
      multiple: false,
      upsert: true,
      label: 'Valid from'
    },
    {
      name: 'valid_until',
      type: 'date',
      mandatoryType: 'customizable',
      editDefault: true,
      multiple: false,
      upsert: true,
      label: 'Valid until'
    },
    {
      name: 'x_opencti_score',
      type: 'numeric',
      mandatoryType: 'customizable',
      editDefault: true,
      multiple: false,
      upsert: true,
      label: 'Score'
    },
    { name: 'x_opencti_detection', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true },
    {
      name: 'x_opencti_main_observable_type',
      type: 'string',
      mandatoryType: 'external',
      editDefault: true,
      multiple: false,
      upsert: true,
      label: 'Main observable type'
    },
    {
      name: 'x_mitre_platforms',
      type: 'string',
      mandatoryType: 'customizable',
      editDefault: true,
      multiple: true,
      upsert: true,
      label: 'Platforms'
    },
  ],
  relations: [],
  representative: (stix: StixIndicator) => {
    return stix.name;
  },
  converter: convertIndicatorToStix
};

registerDefinition(INDICATOR_DEFINITION);
