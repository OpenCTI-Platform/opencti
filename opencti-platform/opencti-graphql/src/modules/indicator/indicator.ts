import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_INDICATOR, type StixIndicator, type StoreEntityIndicator } from './indicator-types';
import convertIndicatorToStix from './indicator-converter';
import { killChainPhases, objectOrganization } from '../../schema/stixRefRelationship';
import { revoked } from '../../schema/attribute-definition';
import { RELATION_DERIVED_FROM } from '../../schema/stixCoreRelationship';
import { REL_BUILT_IN } from '../../database/stix';

const INDICATOR_DEFINITION: ModuleDefinition<StoreEntityIndicator, StixIndicator> = {
  type: {
    id: 'indicator',
    name: ENTITY_TYPE_INDICATOR,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: false
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_INDICATOR]: [{ src: 'pattern' }]
    },
    resolvers: {},
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'pattern_type', label: 'Pattern type', type: 'string', format: 'vocabulary', vocabularyCategory: 'pattern_type_ov', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'pattern_version', label: 'Pattern version', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'pattern', label: 'Pattern', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'indicator_types', label: 'Indicator types', type: 'string', format: 'vocabulary', vocabularyCategory: 'indicator_type_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    { name: 'valid_from', label: 'Valid from', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'valid_until', label: 'Valid until', type: 'date', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_score', label: 'Score', type: 'numeric', precision: 'integer', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_detection', label: 'Is detected', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_opencti_main_observable_type', label: 'Main observable type', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'x_mitre_platforms', label: 'Platforms', type: 'string', format: 'short', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
    {
      name: 'decay_next_reaction_date',
      type: 'date',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      label: 'Decay next reaction date',
      isFilterable: false
    },
    {
      name: 'decay_base_score',
      type: 'numeric',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      label: 'Decay base score',
      isFilterable: false,
      precision: 'integer',
    },
    {
      name: 'decay_base_score_date',
      type: 'date',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      label: 'Decay base score date',
      isFilterable: false,
    },
    {
      name: 'decay_history',
      type: 'object',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: true,
      label: 'Decay history',
      isFilterable: false,
      format: 'flat'
    },
    {
      name: 'decay_applied_rule',
      type: 'object',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: true,
      label: 'Decay applied rule',
      isFilterable: false,
      format: 'flat'
    },
    { ...revoked, isFilterable: true },
  ],
  relations: [
    {
      name: RELATION_DERIVED_FROM,
      targets: [
        { name: ENTITY_TYPE_INDICATOR, type: REL_BUILT_IN },
      ]
    }
  ],
  relationsRefs: [objectOrganization, killChainPhases],
  representative: (stix: StixIndicator) => {
    return stix.name;
  },
  converter: convertIndicatorToStix
};

registerDefinition(INDICATOR_DEFINITION);
