import { assoc, dissoc, pick, pipe, head, includes } from 'ramda';
import * as R from 'ramda';
import { version as uuidVersion } from 'uuid';
import uuidTime from 'uuid-time';
import { FunctionalError } from '../config/errors';
import { isStixDomainObjectIdentity, isStixDomainObjectLocation } from '../schema/stixDomainObject';
import { ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../schema/stixCyberObservableObject';
import {
  isStixInternalMetaRelationship,
  isStixMetaRelationship,
  RELATION_CREATED_BY,
} from '../schema/stixMetaRelationship';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { multipleAttributes } from '../schema/fieldDataAdapter';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import { IDS_ALIASES } from '../schema/general';

export const STIX_SPEC_VERSION = '2.1';

const convertTypeToStixType = (type) => {
  if (isStixDomainObjectIdentity(type)) {
    return 'identity';
  }
  if (isStixDomainObjectLocation(type)) {
    return 'location';
  }
  if (type === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    return 'file';
  }
  return type.toLowerCase();
};

export const buildStixData = (entityData, extra = {}, onlyBase = false) => {
  const type = entityData.entity_type;
  let finalData = pipe(
    assoc('id', entityData.standard_id),
    assoc('type', convertTypeToStixType(type)),
    dissoc('standard_id'),
    dissoc('internal_id'),
    dissoc(IDS_ALIASES),
    dissoc('entity_type')
  )(entityData);
  // Relationships
  if (isStixCoreRelationship(type)) {
    finalData = pipe(
      assoc('source_ref', extra.from ? extra.from.standard_id : null),
      assoc('target_ref', extra.to ? extra.to.standard_id : null)
    )(finalData);
  }
  // Reserved keywords in Grakn
  if (finalData.attribute_abstract) {
    finalData = pipe(dissoc('attribute_abstract'), assoc('abstract', entityData.attribute_abstract))(finalData);
  }
  if (finalData.attribute_date) {
    finalData = pipe(dissoc('attribute_date'), assoc('date', entityData.attribute_date))(finalData);
  }
  if (finalData.attribute_date) {
    finalData = pipe(dissoc('attribute_key'), assoc('key', entityData.attribute_key))(finalData);
  }
  if (onlyBase) {
    return pick(['id', 'type', 'spec_version', 'source_ref', 'target_ref', 'start_time', 'stop_time'], finalData);
  }
  return finalData;
};

export const convertStixMetaRelationshipToStix = (data, extra) => {
  const entityType = data.entity_type;
  let finalData = buildStixData(extra.from, {}, true);
  if (isStixInternalMetaRelationship(entityType)) {
    finalData = assoc(entityType.replace('-', '_'), [buildStixData(extra.to)], finalData);
  } else {
    finalData = assoc(
      `${entityType.replace('-', '_')}_ref${entityType !== RELATION_CREATED_BY ? 's' : ''}`,
      entityType !== RELATION_CREATED_BY ? [extra.to.standard_id] : extra.to.standard_id,
      finalData
    );
  }
  return finalData;
};

export const convertStixCyberObservableRelationshipToStix = (data, extra) => {
  const entityType = data.entity_type;
  let finalData = buildStixData(extra.from, {}, true);
  finalData = assoc(`${entityType.replace('-', '_')}_ref`, extra.to.standard_id, finalData);
  return finalData;
};

export const convertDataToStix = async (data, eventType = null, eventExtraData = {}) => {
  if (!data) {
    /* istanbul ignore next */
    throw FunctionalError('No data provided to STIX converter');
  }
  const entityType = data.entity_type;
  const onlyBase = eventType === 'delete';
  let finalData;
  if (isStixObject(entityType)) {
    finalData = buildStixData(data, {}, onlyBase);
  }
  if (isStixCoreRelationship(entityType)) {
    finalData = buildStixData(data, eventExtraData, onlyBase);
  }
  if (isStixSightingRelationship(entityType)) {
    finalData = buildStixData(data, eventExtraData, onlyBase);
  }
  if (isStixMetaRelationship(entityType)) {
    finalData = convertStixMetaRelationshipToStix(data, eventExtraData);
  }
  if (isStixCyberObservableRelationship(entityType)) {
    finalData = convertStixCyberObservableRelationshipToStix(data, eventExtraData);
  }
  if (!finalData) {
    throw FunctionalError(`The converter is not able to convert this type of entity: ${entityType}`);
  }
  if (eventType === 'update' && eventExtraData.key) {
    return assoc(
      eventExtraData.key,
      includes(eventExtraData.key, multipleAttributes) ? eventExtraData.value : head(eventExtraData.value),
      finalData
    );
  }
  return finalData;
};

export const mergeStixIds = (ids, existingIds) => {
  const wIds = Array.isArray(ids) ? ids : [ids];
  const data = R.map((stixId) => {
    const segments = stixId.split('--');
    const [, uuid] = segments;
    const isTransient = uuidVersion(uuid) === 1;
    const timestamp = isTransient ? uuidTime.v1(uuid) : null;
    return { id: stixId, uuid, timestamp };
  }, existingIds);
  const standardIds = R.filter((d) => !d.timestamp, data);
  const transientIds = R.filter((d) => d.timestamp, data);
  const orderedTransient = R.sort((a, b) => b.timestamp - a.timestamp, transientIds);
  for (let index = 0; index < wIds.length; index += 1) {
    const id = wIds[index];
    if (!existingIds.includes(id)) {
      // If classic uuid, just add it.
      const [, newUuid] = id.split('--');
      if (uuidVersion(newUuid) !== 1) {
        standardIds.push({ id });
      } else {
        orderedTransient.unshift({ id }); // Add the new element in first
      }
    }
  }
  // Ensure max length
  const keptTimedUUID = orderedTransient.length > 5 ? orderedTransient.slice(0, 5) : orderedTransient;
  // Return the new list
  return R.map((s) => s.id, [...standardIds, ...keptTimedUUID]);
};
