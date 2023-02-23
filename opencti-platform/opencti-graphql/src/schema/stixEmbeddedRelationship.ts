import { isStixMetaRelationship, } from './stixMetaRelationship';
import { isStixCyberObservableRelationship, } from './stixCyberObservableRelationship';
import type { BasicStoreObject } from '../types/store';
import { buildRefRelationKey, ID_INFERRED, ID_INTERNAL } from './general';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { schemaRelationsRefDefinition } from './schema-relationsRef';

export const isStixEmbeddedRelationship = (type: string): boolean => isStixMetaRelationship(type) || isStixCyberObservableRelationship(type);

export const isSingleStixEmbeddedRelationship = (type: string): boolean => schemaRelationsRefDefinition.getDatabaseNames().includes(type)
  && !schemaRelationsRefDefinition.isMultipleDatabaseName(type);

export const isSingleStixEmbeddedRelationshipInput = (input: string): boolean => schemaRelationsRefDefinition.getInputNames().includes(input)
  && !schemaRelationsRefDefinition.isMultipleName(input);

// eslint-disable-next-line
export const instanceMetaRefsExtractor = (relationshipType: string, isInferred: boolean, data: BasicStoreObject) => {
  const refField = isStixMetaRelationship(relationshipType) && isInferred ? ID_INFERRED : ID_INTERNAL;
  const field = buildRefRelationKey(relationshipType, refField);
  const anyData = data as any; // TODO JRI Find a way to not use any
  return anyData[field] ?? [];
};
const RELATIONS_STIX_ATTRIBUTES = ['source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
const ALL_STIX_REFS = [...schemaRelationsRefDefinition.getStixNames(), ...RELATIONS_STIX_ATTRIBUTES];
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
