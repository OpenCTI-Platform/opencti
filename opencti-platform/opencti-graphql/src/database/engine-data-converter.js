import * as R from 'ramda';
import { DatabaseError } from '../config/errors';
import { BASE_TYPE_RELATION, isAbstract, REL_INDEX_PREFIX, RULE_PREFIX } from '../schema/general';
import { isSingleRelationsRef } from '../schema/stixEmbeddedRelationship';
import { convertTypeToStixType } from './stix-converter';
import { MAX_EVENT_LOOP_PROCESSING_TIME } from './utils';

const elBuildRelation = (type, connection) => {
  return {
    [type]: null,
    [`${type}Id`]: connection.internal_id,
    [`${type}Role`]: connection.role,
    [`${type}Name`]: connection.name,
    [`${type}Type`]: connection.types.find((connectionType) => !isAbstract(connectionType)),
  };
};
const elMergeRelation = (concept, fromConnection, toConnection) => {
  if (!fromConnection || !toConnection) {
    throw DatabaseError('Reconstruction of the relation fail', concept.internal_id);
  }
  const from = elBuildRelation('from', fromConnection);
  from.source_ref = `${convertTypeToStixType(from.fromType)}--temporary`;
  const to = elBuildRelation('to', toConnection);
  to.target_ref = `${convertTypeToStixType(to.toType)}--temporary`;
  return R.mergeAll([concept, from, to]);
};
const elRebuildRelation = (concept) => {
  if (concept.base_type === BASE_TYPE_RELATION) {
    const { connections } = concept;
    const entityType = concept.entity_type;
    const fromConnection = R.find((connection) => connection.role === `${entityType}_from`, connections);
    const toConnection = R.find((connection) => connection.role === `${entityType}_to`, connections);
    const relation = elMergeRelation(concept, fromConnection, toConnection);
    relation.relationship_type = relation.entity_type;
    return R.dissoc('connections', relation);
  }
  return concept;
};
const elDataConverter = (esHit, withoutRels = false) => {
  const elementData = esHit._source;
  const data = {
    _index: esHit._index,
    _id: esHit._id,
    id: elementData.internal_id,
    sort: esHit.sort,
    ...elRebuildRelation(elementData),
  };
  const entries = Object.entries(data);
  const ruleInferences = [];
  for (let index = 0; index < entries.length; index += 1) {
    const [key, val] = entries[index];
    if (key.startsWith(RULE_PREFIX)) {
      const rule = key.substring(RULE_PREFIX.length);
      const ruleDefinitions = Object.values(val);
      for (let rIndex = 0; rIndex < ruleDefinitions.length; rIndex += 1) {
        const { inferred, explanation } = ruleDefinitions[rIndex];
        const attributes = R.toPairs(inferred).map((s) => ({ field: R.head(s), value: String(R.last(s)) }));
        ruleInferences.push({ rule, explanation, attributes });
      }
      data[key] = val;
    } else if (key.startsWith(REL_INDEX_PREFIX)) {
      // Rebuild rel to stix attributes
      if (withoutRels) {
        delete data[key];
      } else {
        const rel = key.substring(REL_INDEX_PREFIX.length);
        const [relType] = rel.split('.');
        data[relType] = isSingleRelationsRef(data.entity_type, relType) ? R.head(val) : [...(data[relType] ?? []), ...val];
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
  return data;
};

export const elConvertHitsToMap = async (elements, opts) => {
  const { mapWithAllIds = false } = opts;
  const convertedHitsMap = {};
  let startProcessingTime = new Date().getTime();
  for (let n = 0; n < elements.length; n += 1) {
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
    // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  return convertedHitsMap;
};

export const elConvertHits = async (data, opts = {}) => {
  const { withoutRels = false } = opts;
  const convertedHits = [];
  let startProcessingTime = new Date().getTime();
  for (let n = 0; n < data.length; n += 1) {
    const hit = data[n];
    const element = elDataConverter(hit, withoutRels);
    convertedHits.push(element);
    // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  return convertedHits;
};
