import { ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE, type StixIngestionDeduplicationRule, type StoreEntityIngestionDeduplicationRule } from './ingestionDeduplicationRule-types';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { INGESTION_DEDUPLICATION_FEATURE_FLAG } from '../../config/conf';
import convertIngestionDeduplicationRuleToStix from './ingestionDeduplicationRule-converter';

const INGESTION_DEDUPLICATION_RULE_DEFINITION: ModuleDefinition<StoreEntityIngestionDeduplicationRule, StixIngestionDeduplicationRule> = {
  type: {
    id: 'ingestionDeduplicationRule',
    name: ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    // One rule per user and type: a concurrent creation lands on the same id and the entity lock
    definition: {
      [ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE]: [{ src: 'user_id' }, { src: 'target_type' }],
    },
    resolvers: {},
  },
  attributes: [
    { name: 'user_id', label: 'User', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag: INGESTION_DEDUPLICATION_FEATURE_FLAG },
    { name: 'target_type', label: 'Target type', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: false, upsert: false, isFilterable: true, featureFlag: INGESTION_DEDUPLICATION_FEATURE_FLAG },
    { name: 'excluded_fields', label: 'Excluded fields', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false, featureFlag: INGESTION_DEDUPLICATION_FEATURE_FLAG },
    { name: 'ttl', label: 'Expiration', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false, featureFlag: INGESTION_DEDUPLICATION_FEATURE_FLAG },
  ],
  relations: [],
  representative: (stix: StixIngestionDeduplicationRule) => {
    return stix.target_type;
  },
  converter_2_1: convertIngestionDeduplicationRuleToStix,
};

registerDefinition(INGESTION_DEDUPLICATION_RULE_DEFINITION);
