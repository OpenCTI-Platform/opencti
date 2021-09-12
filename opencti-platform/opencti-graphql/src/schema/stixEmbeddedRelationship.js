import * as R from 'ramda';
import {
  FIELD_META_STIX_RELATIONS_TO_STIX_ATTRIBUTE,
  isSingleStixMetaRelationship,
  isStixMetaRelationship,
  STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD,
  STIX_META_RELATION_TO_FIELD,
  isSingleStixMetaRelationshipInput,
} from './stixMetaRelationship';
import {
  FIELD_CYBER_RELATIONS_TO_STIX_ATTRIBUTE,
  isSingleStixCyberObservableRelationship,
  isStixCyberObservableRelationship,
  STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
  STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD,
  isSingleStixCyberObservableRelationshipInput,
} from './stixCyberObservableRelationship';

export const INPUTS_RELATIONS_TO_STIX_ATTRIBUTE = {
  ...FIELD_META_STIX_RELATIONS_TO_STIX_ATTRIBUTE,
  ...FIELD_CYBER_RELATIONS_TO_STIX_ATTRIBUTE,
};
export const META_STIX_ATTRIBUTES = Object.values(INPUTS_RELATIONS_TO_STIX_ATTRIBUTE);

export const STIX_ATTRIBUTE_TO_META_FIELD = {
  ...STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD,
  ...STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
};
export const META_FIELD_ATTRIBUTES = Object.values(STIX_ATTRIBUTE_TO_META_FIELD);

export const STIX_EMBEDDED_RELATION_TO_FIELD = {
  ...STIX_META_RELATION_TO_FIELD,
  ...STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD,
};
export const FIELD_ATTRIBUTE_TO_EMBEDDED_RELATION = R.mergeAll(
  Object.keys(STIX_EMBEDDED_RELATION_TO_FIELD).map((k) => ({ [STIX_EMBEDDED_RELATION_TO_FIELD[k]]: k }))
);

export const isStixEmbeddedRelationship = (type) =>
  isStixMetaRelationship(type) || isStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationship = (type) =>
  isSingleStixMetaRelationship(type) || isSingleStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationshipInput = (input) =>
  isSingleStixMetaRelationshipInput(input) || isSingleStixCyberObservableRelationshipInput(input);

export const instanceMetaRefsExtractor = (data) => {
  return [...META_STIX_ATTRIBUTES].map((key) => data[key] || []).flat();
};
const RELATIONS_STIX_ATTRIBUTES = ['source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
const ALL_STIX_REFS = [...META_STIX_ATTRIBUTES, ...RELATIONS_STIX_ATTRIBUTES];
export const stixRefsExtractor = (data, idGenerator) => {
  return ALL_STIX_REFS.map((key) => {
    // stix embedding (label, external ref, kill chain)
    if (key === 'external_references' && data[key]) {
      return data[key].map((e) => idGenerator('External-Reference', e));
    }
    if (key === 'kill_chain_phases' && data[key]) {
      return data[key].map((e) => idGenerator('Kill-Chain-Phase', e));
    }
    if (key === 'labels' && data[key]) {
      return data[key].map((e) => idGenerator('Label', { value: e }));
    }
    // cyber embedding (x509-v3-extensions, body_multipart)
    if (key === 'x509_v3_extensions' && data[key]) {
      return data[key].map((e) => idGenerator('X509-V3-Extensions-Type', e));
    }
    if (key === 'body_multipart' && data[key]) {
      return data[key].map((e) => idGenerator('Email-Mime-Part-Type', e));
    }
    return data[key] || [];
  }).flat();
};
