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
import type { BasicStoreObject } from '../types/store';
import { buildRefRelationKey, ID_INFERRED, ID_INTERNAL } from './general';
import { STIX_EXT_OCTI } from '../types/stix-extensions';

export const INPUTS_RELATIONS_TO_STIX_ATTRIBUTE: { [k: string]: string } = {
  ...FIELD_META_STIX_RELATIONS_TO_STIX_ATTRIBUTE,
  ...FIELD_CYBER_RELATIONS_TO_STIX_ATTRIBUTE,
};
export const META_STIX_ATTRIBUTES = Object.values(INPUTS_RELATIONS_TO_STIX_ATTRIBUTE);

export const STIX_ATTRIBUTE_TO_META_FIELD: { [k: string]: string } = {
  ...STIX_ATTRIBUTE_TO_META_RELATIONS_FIELD,
  ...STIX_ATTRIBUTE_TO_CYBER_OBSERVABLE_FIELD,
};
export const metaFieldAttributes = () => {
  return Object.values(STIX_ATTRIBUTE_TO_META_FIELD);
};

export const stixEmbeddedRelationToField: () => { [k: string]: string } = () => {
  return {
    ...STIX_META_RELATION_TO_FIELD,
    ...STIX_CYBER_OBSERVABLE_RELATION_TO_FIELD,
  };
};
export const fieldAttributeToEmbeddedRelation = () => R.mergeAll(
  Object.keys(stixEmbeddedRelationToField()).map((k) => ({ [stixEmbeddedRelationToField()[k]]: k }))
);

export const isStixEmbeddedRelationship = (type: string): boolean => isStixMetaRelationship(type) || isStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationship = (type: string): boolean => isSingleStixMetaRelationship(type) || isSingleStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationshipInput = (input: string): boolean => isSingleStixMetaRelationshipInput(input) || isSingleStixCyberObservableRelationshipInput(input);

// eslint-disable-next-line
export const instanceMetaRefsExtractor = (relationshipType: string, isInferred: boolean, data: BasicStoreObject) => {
  const refField = isStixMetaRelationship(relationshipType) && isInferred ? ID_INFERRED : ID_INTERNAL;
  const field = buildRefRelationKey(relationshipType, refField);
  const anyData = data as any; // TODO JRI Find a way to not use any
  return anyData[field] ?? [];
};
const RELATIONS_STIX_ATTRIBUTES = ['source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
const ALL_STIX_REFS = [...META_STIX_ATTRIBUTES, ...RELATIONS_STIX_ATTRIBUTES];
// eslint-disable-next-line
export const stixRefsExtractor = (data: any, idGenerator: (key: string, data: unknown) => string) => {
  return ALL_STIX_REFS.map((key) => {
    // stix embedding (label, external ref, kill chain)
    if (key === 'external_references' && data[key]) {
      // eslint-disable-next-line
      return data[key].map((e: any) => idGenerator('External-Reference', e));
    }
    if (key === 'kill_chain_phases' && data[key]) {
      // eslint-disable-next-line
      return data[key].map((e: any) => idGenerator('Kill-Chain-Phase', e));
    }
    if (key === 'labels' && data[key]) {
      // eslint-disable-next-line
      return data[key].map((e: any) => idGenerator('Label', { value: e }));
    }
    if (key === 'body_multipart' && data[key]) {
      // eslint-disable-next-line
      return data[key].map((e: any) => idGenerator('Email-Mime-Part-Type', e));
    }
    if (key === 'granted_refs' && data.extensions[STIX_EXT_OCTI][key]) {
      // eslint-disable-next-line
      return data.extensions[STIX_EXT_OCTI][key];
    }
    return data[key] || [];
  }).flat();
};
