import { v4 as uuidv4 } from 'uuid';
import convertRetentionRuleToStix from './retentionRules-converter';
import { ENTITY_TYPE_RETENTION_RULE, type StixRetentionRule, type StoreEntityRetentionRule } from './retentionRules-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { RETENTION_SCOPE_VALUES, RETENTION_UNIT_VALUES } from '../../manager/retentionManager';

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
      editDefault: true,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'filters',
      label: 'Filters',
      type: 'string',
      format: 'text',
      mandatoryType: 'external',
      editDefault: true,
      multiple: false,
      upsert: false,
      isFilterable: false,
    },
    {
      name: 'max_retention',
      label: 'Maximum retention',
      type: 'numeric',
      precision: 'integer',
      mandatoryType: 'external',
      editDefault: true,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'retention_unit',
      label: 'Maximum retention unit',
      type: 'string',
      format: 'enum',
      values: RETENTION_UNIT_VALUES,
      mandatoryType: 'no',
      editDefault: true,
      multiple: false,
      upsert: false,
      isFilterable: true,
    },
    {
      name: 'scope',
      label: 'Scope',
      type: 'string',
      format: 'enum',
      values: RETENTION_SCOPE_VALUES,
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
      isFilterable: true,
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
      isFilterable: true,
    },
  ],
  relations: [],
  representative: (instance: StixRetentionRule) => {
    return instance.name;
  },
  converter_2_1: convertRetentionRuleToStix,
};

registerDefinition(RETENTION_RULE_DEFINITION);
