import * as R from 'ramda';
import { UnsupportedError } from '../config/errors';
import { IDS_ALIASES, IDS_STIX } from './general';

export const multipleAttributes = [
  IDS_STIX,
  'aliases',
  IDS_ALIASES,
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
  'labels',
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
export const booleanAttributes = [
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
    R.map((d) => [d[info.key], d[info.value]]),
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
    R.map(([lab, val]) => ({ [key]: lab, [value]: val }))
  )(attributeValue);
};
