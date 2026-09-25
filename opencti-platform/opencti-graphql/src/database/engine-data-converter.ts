import { isNotEmptyField } from './utils';
import { logApp } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { isStixRefUnidirectionalRelationship } from '../schema/stixRefRelationship';
import { BASE_TYPE_RELATION, isAbstract, REL_INDEX_PREFIX, RULE_PREFIX } from '../schema/general';
import { isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { convertTypeToStixType } from './stix-2-1-converter';
import { asyncMap } from '../utils/data-processing';
import { doYield } from '../utils/eventloop-utils';
import type { BasicStoreBase, BasicStoreRelation, StoreConnection } from '../types/store';

export const INNER_HITS_WINDOWS_SIZE = 100;

type FromRelationData = {
  from: null;
  fromId: string;
  fromRole: string;
  fromName: string;
  fromType: string;
  source_ref: string;
};
type ToRelationData = {
  to: null;
  toId: string;
  toRole: string;
  toName: string;
  toType: string;
  target_ref: string;
};
const elBuildRelation = (type: string, connection: StoreConnection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: connection.types.find((connectionType) => !isAbstract(connectionType)),
  };
};
const elBuildFromRelation = (connection: StoreConnection): FromRelationData => {
  const fromRelation = elBuildRelation('from', connection);
  fromRelation.source_ref = `${convertTypeToStixType(fromRelation.fromType as string)}--temporary`;
  return fromRelation as FromRelationData;
};
const elBuildToRelation = (connection: StoreConnection): ToRelationData => {
  const toRelation = elBuildRelation('to', connection);
  toRelation.target_ref = `${convertTypeToStixType(toRelation.toType as string)}--temporary`;
  return toRelation as ToRelationData;
};
const elBuildInnerRelations = (
  concept: { internal_id: string; base_type: string; entity_type: string },
  fromConnection: StoreConnection | undefined,
  toConnection: StoreConnection | undefined,
): { from: FromRelationData; to: ToRelationData } => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('Reconstruction of the relation fail', concept.internal_id);
  }
  const from = elBuildFromRelation(fromConnection);
  const to = elBuildToRelation(toConnection);
  return { from, to };
};
export const elRebuildRelation = (concept: Record<string, any>) => {
  if (concept.base_type === BASE_TYPE_RELATION) {
    const { connections } = concept as BasicStoreRelation;
    const entityType = concept.entity_type;
    const fromConnection = connections.find((connection) => connection.role === `${entityType}_from`);
    const toConnection = connections.find((connection) => connection.role === `${entityType}_to`);
    const { from, to } = elBuildInnerRelations(concept as BasicStoreRelation, fromConnection, toConnection);
    Object.assign(concept, from, to);
    concept.relationship_type = concept.entity_type;
    delete concept.connections;
  }
  return concept;
};
const processInnerHits = (data: Record<string, any>, innerHits: any, internalId: string) => {
  Object.keys(innerHits).forEach((innerHitKey) => {
    const nestedHits = innerHits[innerHitKey];
    if (nestedHits?.hits?.hits) {
      if (nestedHits?.hits?.hits.length === INNER_HITS_WINDOWS_SIZE) {
        logApp.warn('Inner hits limitation reached', { id: internalId, key: innerHitKey });
      }
      const matchedDocs = nestedHits.hits.hits.map((h: any) => h._source);
      const paths = innerHitKey.split('.');
      let current = data;
      for (let i = 0; i < paths.length - 1; i += 1) {
        const path = paths[i];
        if (!current[path]) {
          current[path] = {};
        }
        current = current[path];
      }
      current[paths[paths.length - 1]] = matchedDocs;
    }
  });
};

const elDataConverter = <T>(esHit: any): T => {
  const data: Record<string, any> = esHit._source;
  data._index = esHit._index;
  data._id = esHit._id;
  data.id = data.internal_id;
  data.sort = esHit.sort;
  elRebuildRelation(data);
  if (isNotEmptyField(esHit.fields)) {
    Object.assign(data, esHit.fields);
  }
  // Inner elements mapping
  if (esHit.inner_hits) {
    processInnerHits(data, esHit.inner_hits, data.internal_id);
  }
  // Rule inference mapping
  const ruleInferences = [];
  // Only get all object keys here
  // Values will be loaded dynamically only if needed for rel_*/i_rule_* prefixed keys
  const keys = Object.keys(data);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (keys[index].startsWith(RULE_PREFIX)) {
      const val = data[key];
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions: any = Object.values(val);
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = Object.entries(inferred).map(([field, value]) => ({ field, value: String(value) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      const val = data[key];
      const rel = key.substring(REL_INDEX_PREFIX.length);
      const [relType] = rel.split('.');
      if (isSingleRelationsRef(data.entity_type, relType)) {
        data[relType] = val[0];
      } else {
        const relData = [...(data[relType] ?? []), ...val];
        data[relType] = isStixRefUnidirectionalRelationship(relType) ? [...new Set(relData)] : relData;
      }
    }
  }
  if (ruleInferences.length > 0) {
    data.x_opencti_inferences = ruleInferences;
  }
  if (data.event_data) {
    data.event_data = JSON.stringify(data.event_data);
  }
  return data as T;
};
// endregion
export const elConvertHitsToMap = async <T extends BasicStoreBase>(
  elements: T[],
  opts: { mapWithAllIds?: boolean } = {},
): Promise<Record<string, T>> => {
  const { mapWithAllIds = false } = opts;
  const convertedHitsMap: Record<string, T> = {};
  for (let n = 0; n < elements.length; n += 1) {
    await doYield();
    const element = elements[n];
    convertedHitsMap[element.internal_id] = element;
    if (mapWithAllIds) {
      // Add the standard id key
      if (element.standard_id) {
        convertedHitsMap[element.standard_id] = element;
      }
      // Add the stix ids keys
      (element.x_opencti_stix_ids ?? []).forEach((id) => {
        convertedHitsMap[id] = element;
      });
    }
  }
  return convertedHitsMap;
};

export const elConvertHits = async <T extends BasicStoreBase>(data: any): Promise<T[]> => asyncMap<any, T>(data, (hit) => elDataConverter<T>(hit));
