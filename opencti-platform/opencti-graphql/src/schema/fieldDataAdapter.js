import * as R from 'ramda';
import { UnsupportedError } from '../config/errors';
import { INTERNAL_IDS_ALIASES, IDS_STIX } from './general';
import { STANDARD_HASHES } from './identifier';
import { isDatedInternalObject } from './internalObject';
import { isStixCoreObject } from './stixCoreObject';
import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isStixMetaObject } from './stixMetaObject';
import { isStixDomainObject } from './stixDomainObject';

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
  'labels',
  'external_references',
  'kill_chain_phases',
  'tags',
  'bookmarks',
];
export const statsDateAttributes = [
  'created_at',
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  'published',
  'valid_from',
  'valid_until',
];
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
  'observable_date',
  'event_date',
  'timestamp',
  'received_time',
  'processed_time',
  'completed_time',
];
export const numericAttributes = [
  'attribute_order',
  'base_score',
  'confidence',
  'number_observed',
  'x_opencti_order',
  'x_opencti_report_status',
  'import_expected_number',
  'import_processed_number',
  'x_opencti_score',
  'size',
  'attribute_count',
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
];
export const numericOrBooleanAttributes = [...numericAttributes, ...booleanAttributes];
export const dictAttributes = { hashes: { key: 'algorithm', value: 'hash' } };

export const isDictionaryAttribute = (key) => dictAttributes[key];
export const isBooleanAttribute = (key) => booleanAttributes.includes(key);
export const isMultipleAttribute = (key) => multipleAttributes.includes(key);

// Must be call as soon as possible in the according resolvers
export const apiAttributeToComplexFormat = (attribute, data) => {
  const info = dictAttributes[attribute];
  if (!info) {
    throw UnsupportedError('Cant deserialize this attribute because its not a dictionary', { attribute });
  }
  const inputs = Array.isArray(data) ? data : [data];
  return R.pipe(
    R.map((d) => {
      const keyValue = d[info.key];
      const isStandardHash = STANDARD_HASHES.includes(keyValue.toUpperCase());
      const infoKey = isStandardHash ? keyValue.toUpperCase() : keyValue;
      return [infoKey, d[info.value]];
    }),
    R.fromPairs
  )(inputs);
};
// Must only be call in generic resolvers for data output
export const complexAttributeToApiFormat = (dataKey, instance) => {
  const attributeValue = instance[dataKey];
  const info = dictAttributes[dataKey];
  if (!info) {
    throw UnsupportedError('Cant serialize this attribute -> not a dictionary', { attributeValue });
  }
  const { key, value } = info;
  return R.pipe(
    R.toPairs,
    R.map(([lab, val]) => {
      const isStandardHash = STANDARD_HASHES.includes(lab.toUpperCase());
      const labValue = isStandardHash ? lab.toUpperCase() : lab;
      return { [key]: labValue, [value]: val };
    })
  )(attributeValue);
};

export const isUpdatedAtObject = (type) => {
  return (
    isDatedInternalObject(type) ||
    isStixMetaObject(type) ||
    isStixCoreObject(type) ||
    isStixCoreRelationship(type) ||
    isStixSightingRelationship(type)
  );
};

export const isModifiedObject = (type) => {
  return (
    isStixMetaObject(type) ||
    isStixDomainObject(type) ||
    isStixCoreRelationship(type) ||
    isStixSightingRelationship(type)
  );
};
