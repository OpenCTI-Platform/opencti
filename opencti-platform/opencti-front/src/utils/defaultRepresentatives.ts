/* eslint-disable @typescript-eslint/no-explicit-any */
import * as R from 'ramda';
import { isDateStringNone } from '../components/i18n';
import { truncate } from './String';
import { dateFormat } from './Time';

export const isFieldForIdentifier = (fieldName?: string) => {
  if (!fieldName) {
    return false;
  }
  return fieldName === 'id'
    || fieldName.endsWith('.id')
    || fieldName.endsWith('_id')
    || fieldName.endsWith('_ids');
};

export const defaultDate = (n: any) => {
  if (!n) return '';
  if (!isDateStringNone(n.start_time)) {
    return n.start_time;
  }
  if (!isDateStringNone(n.first_seen)) {
    return n.first_seen;
  }
  if (!isDateStringNone(n.first_observed)) {
    return n.first_observed;
  }
  if (!isDateStringNone(n.valid_from)) {
    return n.valid_from;
  }
  if (!isDateStringNone(n.published)) {
    return n.published;
  }
  if (!isDateStringNone(n.created)) {
    return n.created;
  }
  if (!isDateStringNone(n.created_at)) {
    return n.created_at;
  }
  return null;
};

export const defaultType = (n: any, t: (key: string) => string) => {
  if (n.parent_types.includes('basic-relationship')) {
    return t(`relationship_${n.entity_type}`);
  }
  return t(`entity_${n.entity_type}`);
};

export const defaultValueMarking = (n: any) => {
  let def = 'Unknown';
  if (n.definition) {
    const definition = R.toPairs(n.definition);
    if (definition[0]) {
      if (definition[0][1].includes(':')) {
        def = definition[0][1];
      } else {
        def = `${definition[0][0]}:${definition[0][1]}`;
      }
    }
  }
  return def;
};

export const defaultKey = (n: any) => {
  if (!n) return null;
  if (n.hashes) {
    return 'hashes';
  }
  if (n.name) {
    return 'name';
  }
  if (n.value) {
    return 'value';
  }
  if (n.observable_value) {
    return 'observable_value';
  }
  if (n.attribute_abstract) {
    return 'attribute_abstract';
  }
  if (n.opinion) {
    return null;
  }
  if (n.abstract) {
    return 'abstract';
  }
  return null;
};

// equivalent to querying representative.main
export const getMainRepresentative = (n: any, fallback = 'Unknown') => {
  if (!n) return '';
  if (n.name === 'Unknown') {
    return 'Unknown';
  }
  if (typeof n.definition === 'object') {
    return defaultValueMarking(n);
  }
  const mainValue: string = n.representative?.main
    || n.name
    || n.label
    || n.observableName
    || n.observable_value
    || n.pattern
    || n.attribute_abstract
    || n.opinion
    || n.value
    || n.definition
    || n.source_name
    || n.phase_name
    || n.result_name
    || n.country
    || n.key
    || n.path
    || (n.template && n.template.name)
    || (n.content && truncate(n.content, 30))
    || (n.hashes
      && (n.hashes['SHA-512']
        || n.hashes['SHA-256']
        || n.hashes['SHA-1']
        || n.hashes.MD5))
      || (n.source_ref_name
        && n.target_ref_name
        && `${truncate(n.source_ref_name, 20)} ➡️ ${truncate(
          n.target_ref_name,
          20,
        )}`)
        || getMainRepresentative((R.head(n.objects?.edges ?? []) as any)?.node)
        || (n.from
          && n.to
          && `${truncate(getMainRepresentative(n.from), 20)} ➡️ ${truncate(
            getMainRepresentative(n.to),
            20,
          )}`)
          || n.main_entity_name
          || fallback;
  return n.x_mitre_id ? `[${n.x_mitre_id}] ${mainValue}` : mainValue;
};

// equivalent to querying representative.secondary
export const getSecondaryRepresentative = (n: any) => {
  if (!n) return '';
  return (
    n.representative?.secondary
    || n.description
    || n.x_opencti_description
    || n.content
    || n.entity_type
    || dateFormat(n.created_at)
  );
};
