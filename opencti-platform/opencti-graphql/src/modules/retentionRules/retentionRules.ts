import { v4 as uuidv4 } from 'uuid';
import convertRetentionRuleToStix from './retentionRules-converter';
import { ENTITY_TYPE_RETENTION_RULE, type StixRetentionRule, type StoreEntityRetentionRule } from './retentionRules-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';

const RETENTION_RULE_DEFINITION: ModuleDefinition<StoreEntityRetentionRule, StixRetentionRule> = {
  type: {
    id: 'retention-rule',
    name: ENTITY_TYPE_RETENTION_RULE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_RETENTION_RULE]: () => uuidv4(),
    },
  },
  attributes: [
    {
      name: 'name',
      label: 'Name',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'filters',
      label: 'Filters',
      type: 'string',
      format: 'text',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    {
      name: 'max_retention',
      label: 'Max retention',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'retention_unit',
      label: 'Retention unit',
      type: 'string',
      format: 'short',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'scope',
      label: 'Scope',
      type: 'string',
      format: 'short',
      mandatoryType: 'external',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'last_execution_date',
      label: 'Last execution date',
      type: 'date',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'last_deleted_count',
      label: 'Last deleted count',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    {
      name: 'remaining_count',
      label: 'Remaining count',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
  ],
  relations: [],
  representative: (instance: StixRetentionRule) => {
    return instance.name;
  },
  converter_2_1: convertRetentionRuleToStix,
};

registerDefinition(RETENTION_RULE_DEFINITION);
