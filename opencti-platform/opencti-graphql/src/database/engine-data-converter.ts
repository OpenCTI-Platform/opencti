import * as R from 'ramda';
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

const elBuildRelation = (type: string, connection: StoreConnection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: connection.types.find((connectionType) => !isAbstract(connectionType)),
  };
};
const elMergeRelation = (
  concept: { internal_id: string; base_type: string; entity_type: string },
  fromConnection: StoreConnection | undefined,
  toConnection: StoreConnection | undefined,
) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('Reconstruction of the relation fail', concept.internal_id);
  }
  const from = elBuildRelation('from', fromConnection);
  from.source_ref = `${convertTypeToStixType(from.fromType as string)}--temporary`;
  const to = elBuildRelation('to', toConnection);
  to.target_ref = `${convertTypeToStixType(to.toType as string)}--temporary`;
  return R.mergeAll([concept, from, to]);
};
export const elRebuildRelation = (concept: { internal_id: string; base_type: string; entity_type: string }) => {
  if (concept.base_type === BASE_TYPE_RELATION) {
    const { connections } = concept as BasicStoreRelation;
    const entityType = concept.entity_type;
    const fromConnection = R.find((connection) => connection.role === `${entityType}_from`, connections);
    const toConnection = R.find((connection) => connection.role === `${entityType}_to`, connections);
    const relation = elMergeRelation(concept as BasicStoreRelation, fromConnection, toConnection);
    relation.relationship_type = relation.entity_type;
    return R.dissoc('connections', relation);
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
  const elementData = esHit._source;
  // Base element mapping
  const data: Record<string, any> = {
    _index: esHit._index,
    _id: esHit._id,
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
    ...(isNotEmptyField(esHit.fields) ? esHit.fields : {}),
  };
  // Inner elements mapping
  if (esHit.inner_hits) {
    processInnerHits(data, esHit.inner_hits, elementData.internal_id);
  }
  // Rule inference mapping
  const ruleInferences = [];
  const entries = Object.entries(data);
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions: any = Object.values(val);
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = R.toPairs(inferred).map((s) => ({ field: R.head(s), value: String(R.last(s)) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
      data[key] = val;
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      const rel = key.substring(REL_INDEX_PREFIX.length);
      const [relType] = rel.split('.');
      if (isSingleRelationsRef(data.entity_type, relType)) {
        data[relType] = R.head(val);
      } else {
        const relData = [...(data[relType] ?? []), ...val];
        data[relType] = isStixRefUnidirectionalRelationship(relType) ? R.uniq(relData) : relData;
      }
    } else {
      data[key] = val;
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
