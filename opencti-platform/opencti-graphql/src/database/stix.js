import { assoc, dissoc, pick, pipe, head, includes } from 'ramda';
import * as R from 'ramda';
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
import { multipleAttributes } from './grakn';

export const STIX_SPEC_VERSION = '2.1';

export const buildStixData = (entityData, extra = {}, onlyBase = false) => {
  let type = entityData.entity_type;
  if (isStixDomainObjectIdentity(type)) {
    type = 'Identity';
  } else if (isStixDomainObjectLocation(type)) {
    type = 'Location';
  } else if (type === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    type = 'File';
  }
  let finalData = pipe(
    dissoc('standard_id'),
    dissoc('internal_id'),
    assoc('id', entityData.standard_id),
    dissoc('entity_type'),
    assoc('type', type.toLowerCase())
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
