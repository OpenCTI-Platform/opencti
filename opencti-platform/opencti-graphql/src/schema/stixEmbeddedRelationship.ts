import type { BasicStoreObject } from '../types/store';
import { buildRefRelationKey, ID_INFERRED, ID_INTERNAL } from './general';
import { STIX_EXT_OCTI } from '../types/stix-extensions';
import { schemaRelationsRefDefinition } from './schema-relationsRef';
import {
  bodyMultipart,
  externalReferences,
  isStixRefRelationship,
  killChainPhases,
  objectLabel
} from './stixRefRelationship';

export const isSingleRelationsRef = (entityType: string, databaseName: string): boolean => isStixRefRelationship(databaseName)
  && !schemaRelationsRefDefinition.isMultipleDatabaseName(entityType, databaseName);

// eslint-disable-next-line
export const instanceMetaRefsExtractor = (relationshipType: string, isInferred: boolean, data: BasicStoreObject) => {
  const refField = isStixRefRelationship(relationshipType) && isInferred ? ID_INFERRED : ID_INTERNAL;
  const field = buildRefRelationKey(relationshipType, refField);
  const anyData = data as any; // TODO JRI Find a way to not use any
  return anyData[field] ?? [];
};

const RELATIONS_STIX_ATTRIBUTES = ['source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
const RELATIONS_EMBEDDED_STIX_ATTRIBUTES = [
  externalReferences.stixName, killChainPhases.stixName, objectLabel.stixName, bodyMultipart.stixName
];
// eslint-disable-next-line
export const stixRefsExtractor = (data: any, idGenerator?: (key: string, data: unknown) => string) => {
  const stixNames = schemaRelationsRefDefinition.getStixNames(data.extensions[STIX_EXT_OCTI].type)
    .filter((key) => !RELATIONS_EMBEDDED_STIX_ATTRIBUTES.includes(key))
    .concat(RELATIONS_STIX_ATTRIBUTES);
  return stixNames.map((key) => {
    if (key === 'granted_refs' && data.extensions[STIX_EXT_OCTI][key]) {
      return data.extensions[STIX_EXT_OCTI][key];
    }
    return data[key] || [];
  }).flat();
};

export const resolvedRefsExtractor = (data: any) => {
  const { type } = data.extensions[STIX_EXT_OCTI];
  const stixNames = schemaRelationsRefDefinition.getStixNames(type)
    .filter((key) => !RELATIONS_EMBEDDED_STIX_ATTRIBUTES.includes(key))
    .concat(RELATIONS_STIX_ATTRIBUTES);
  const mapContent = stixNames.map((key) => {
    if (key === 'granted_refs' && data.extensions[STIX_EXT_OCTI][key]) {
      return [data.extensions[STIX_EXT_OCTI][key], schemaRelationsRefDefinition.relationsRefMap(type).get(key)];
    }
    return data[key] && schemaRelationsRefDefinition.relationsRefMap(type).has(key)
      ? [data[key], schemaRelationsRefDefinition.relationsRefMap(type).get(key)]
      : undefined;
  }).filter((n) => n) as [string, string | undefined][];
  return new Map(mapContent);
};
