import type { KeyValuePair } from 'ramda';
import * as R from 'ramda';
import {
  IDS_STIX,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  INTERNAL_IDS_ALIASES,
  RULE_PREFIX,
} from './general';
import { isDatedInternalObject } from './internalObject';
import { isStixCoreObject } from './stixCoreObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixMetaObject } from './stixMetaObject';
import { isStixDomainObject } from './stixDomainObject';
import { MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS } from './stixCyberObservableRelationship';
import type { StixArtifact, StixFile, StixX509Certificate } from '../types/stix-sco';
import type { HashInput } from '../generated/graphql';

export const jsonAttributes = ['bookmarks', 'connector_state', 'feed_attributes'];
export const multipleAttributes = [
  IDS_STIX,
  'aliases',
  INTERNAL_IDS_ALIASES,
  'grant',
  'indicator_types',
  'infrastructure_types',
  'secondary_motivations',
  'malware_types',
  'architecture_execution_envs',
  'implementation_languages',
  'capabilities',
  'authors',
  'report_types',
  'threat_actor_types',
  'personal_motivations',
  'goals',
  'roles',
  'tool_types',
  'received_lines',
  'environment_variables',
  'languages',
  'x_mitre_platforms',
  'x_mitre_permissions_required',
  'x_opencti_aliases',
  'x_opencti_additional_names',
  'tags',
  'bookmarks',
  'protocols',
  'x_opencti_log_sources',
  'x_opencti_stix_ids',
  'options',
  'entities_ids',
  'x_opencti_files',
  'platform_enable_reference',
  'feed_types',
  'platform_hidden_types',
  // meta
  INPUT_OBJECTS,
  INPUT_MARKINGS,
  INPUT_LABELS,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  // stix cyber observable
  ...MULTIPLE_STIX_CYBER_OBSERVABLE_RELATIONSHIPS_INPUTS,
];
export const noReferenceAttributes = ['x_opencti_graph_data'];
export const runtimeAttributes = ['observable_value', 'createdBy', 'objectMarking'];
export const statsDateAttributes = [
  'created_at',
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  'published',
  'valid_from',
  'valid_until',
  'first_observed',
  'last_observed',
];
export const dateForStartAttributes = ['first_seen', 'start_time', 'valid_from', 'first_observed'];
export const dateForEndAttributes = ['last_seen', 'stop_time', 'valid_until', 'last_observed'];
export const dateForLimitsAttributes = [...dateForStartAttributes, ...dateForEndAttributes];
export const dateAttributes = [
  'created',
  'modified',
  'created_at',
  'i_created_at_day',
  'i_created_at_month',
  'updated_at',
  'first_seen',
  'i_first_seen_day',
  'i_first_seen_month',
  'last_seen',
  'i_last_seen_day',
  'i_last_seen_month',
  'start_time',
  'i_start_time_day',
  'i_start_time_month',
  'stop_time',
  'i_stop_time_day',
  'i_stop_time_month',
  'published',
  'i_published_day',
  'i_published_month',
  'valid_from',
  'i_valid_from_day',
  'i_valid_from_month',
  'valid_until',
  'i_valid_until_day',
  'i_valid_until_month',
  'first_observed',
  'i_first_observed_day',
  'i_first_observed_month',
  'last_observed',
  'i_last_observed_day',
  'i_last_observed_month',
  'observable_date',
  'event_date',
  'timestamp',
  'received_time',
  'processed_time',
  'completed_time',
  'last_run',
  'atime',
  'ctime',
  'mtime',
];
export const numericAttributes = [
  'attribute_order',
  'base_score',
  'confidence',
  'number_observed',
  'x_opencti_order',
  'import_expected_number',
  'import_processed_number',
  'x_opencti_score',
  'size',
  'attribute_count',
  'order',
  'rolling_time',
];
export const booleanAttributes = [
  'completed',
  'revoked',
  'x_opencti_negative',
  'external',
  'default_assignation',
  'active',
  'connector_state_reset',
  'x_opencti_detection',
  'is_family',
  'is_multipart',
  'is_active',
  'is_hidden',
  'is_service_account',
  'is_privileged',
  'can_escalate_privs',
  'is_disabled',
  'is_self_signed',
  'platform_enable_references',
  'auto_new_marking',
  'listen_deletion',
  'no_dependencies',
  'ssl_verify',
  'include_header',
  'otp_activated',
];
export const dictAttributes = ['hashes'];
export const numericOrBooleanAttributes = [...numericAttributes, ...booleanAttributes];

export const isJsonAttribute = (key: string): boolean => jsonAttributes.includes(key);
export const isDictionaryAttribute = (key: string): boolean => dictAttributes.includes(key);
export const isBooleanAttribute = (key: string): boolean => booleanAttributes.includes(key);
export const isNumericAttribute = (key: string): boolean => numericAttributes.includes(key);
export const isDateAttribute = (key: string): boolean => dateAttributes.includes(key);
export const isMultipleAttribute = (key: string): boolean => key.startsWith(RULE_PREFIX) || multipleAttributes.includes(key);
export const isRuntimeAttribute = (key: string): boolean => runtimeAttributes.includes(key);

// Must be call as soon as possible in the according resolvers
export const inputHashesToStix = (data: Array<HashInput>) => {
  const inputs = Array.isArray(data) ? data : [data];
  const convertedInputs = inputs.map((d) => {
    return [d.algorithm.toUpperCase(), d.hash.toLowerCase()] as KeyValuePair<string, string>;
  });
  return R.fromPairs(convertedInputs);
};
// Must only be call in generic resolvers for data output
export const stixHashesToInput = (instance: StixArtifact | StixFile | StixX509Certificate): Array<HashInput> => {
  const attributeValue = instance.hashes ?? {};
  const entries = Object.entries(attributeValue);
  return entries.map(([lab, val]) => {
    return { algorithm: lab.toUpperCase(), hash: val.toLowerCase() };
  });
};

export const isUpdatedAtObject = (type: string): boolean => {
  return (
    isDatedInternalObject(type)
    || isStixMetaObject(type)
    || isStixCoreObject(type)
    || isStixCoreRelationship(type)
    || isStixSightingRelationship(type)
  );
};

export const isModifiedObject = (type: string): boolean => {
  return (
    isStixMetaObject(type)
    || isStixDomainObject(type)
    || isStixCoreRelationship(type)
    || isStixSightingRelationship(type)
  );
};
