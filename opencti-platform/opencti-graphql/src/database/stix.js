import { assoc, dissoc, pick, pipe } from 'ramda';
import { FunctionalError } from '../config/errors';
import {
  isStixObject,
  isStixCoreRelationship,
  isStixMetaRelationship,
  isStixSightingRelationship,
  isStixInternalMetaRelationship,
  RELATION_CREATED_BY,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
} from '../utils/idGenerator';

export const STIX_SPEC_VERSION = '2.1';

export const buildStixData = (entityData, onlyBase = false) => {
  let type = entityData.entity_type;
  if (isStixDomainObjectIdentity(type)) {
    type = 'Identity';
  } else if (isStixDomainObjectLocation(type)) {
    type = 'Location';
  } else if (type === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    type = 'File';
  }
  const finalData = pipe(
    dissoc('standard_id'),
    dissoc('internal_id'),
    assoc('id', entityData.standard_id),
    dissoc('entity_type'),
    assoc('type', type.toLowerCase()),
    // Reserved keywords in Grakn
    dissoc('attribute_abstract'),
    assoc('abstract', entityData.attribute_abstract),
    dissoc('attribute_date'),
    assoc('date', entityData.attribute_date),
    dissoc('attribute_key'),
    assoc('key', entityData.attribute_key)
  )(entityData);
  if (!onlyBase) {
    return pick(['id', 'type', 'spec_version'], entityData);
  }
  return finalData;
};

const convertStixObjectToStix = (data, onlyBase) => {
  const finalData = pipe(
    dissoc('standard_id'),
    dissoc('internal_id'),
    assoc('id', data.standard_id),
    assoc('x_opencti_id', data.internal_id),
    dissoc('entity_type'),
    assoc('type', data.entity_type.toLowerCase()),
    // Reserved keywords in Grakn
    dissoc('attribute_abstract'),
    assoc('abstract', data.attribute_abstract),
    dissoc('attribute_date'),
    assoc('date', data.attribute_date),
    dissoc('attribute_key'),
    assoc('key', data.attribute_key)
  )(data);
  if (onlyBase) {
    return pick(['id', 'type', 'spec_version'], data);
  }
  return finalData;
};

export const convertStixCoreRelationshipToStix = (data, extra = {}, onlyBase = true) => {
  const finalData = pipe(
    dissoc('standard_id'),
    dissoc('internal_id'),
    assoc('id', data.standard_id),
    assoc('x_opencti_id', data.internal_id),
    dissoc('entity_type'),
    assoc('type', 'relationship'),
    // Relation IDs
    assoc('source_ref', extra.from ? extra.from.standard_id : null),
    assoc('target_ref', extra.to ? extra.to.standard_id : null),
    assoc('x_opencti_source_ref', extra.from ? extra.from.internal_id : null),
    assoc('x_opencti_target_ref', extra.to ? extra.to.internal_id : null)
  )(data);
  if (onlyBase) {
    return pick(['id', 'type', 'spec_version'], data);
  }
  return finalData;
};

export const convertStixSightingRelationshipToStix = async (data, extra = {}, onlyBase = true) => {
  const finalData = pipe(
    dissoc('standard_id'),
    dissoc('internal_id'),
    assoc('id', data.standard_id),
    assoc('x_opencti_id', data.internal_id),
    dissoc('entity_type'),
    assoc('type', 'relationship'),
    // Reserved keywords in Grakn
    dissoc('attribute_count'),
    assoc('count', data.attribute_count),
    // Relation IDs
    assoc('sighting_of_ref', extra.from ? extra.from.standard_id : null),
    assoc('where_sighted_refs', extra.to ? [extra.to.standard_id] : null)
  )(data);
  if (onlyBase) {
    return pick(['id', 'type', 'spec_version'], data);
  }
  return finalData;
};

export const convertStixMetaRelationshipToStix = (data, extra) => {
  const entityType = data.entity_type;
  let finalData = convertStixObjectToStix(extra.from, true);
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
  if (isStixObject(entityType)) {
    return convertStixObjectToStix(data, onlyBase);
  }
  if (isStixCoreRelationship(entityType)) {
    return convertStixCoreRelationshipToStix(data, eventExtraData, onlyBase);
  }
  if (isStixSightingRelationship(entityType)) {
    return convertStixSightingRelationshipToStix(data, eventExtraData, onlyBase);
  }
  if (isStixMetaRelationship(entityType)) {
    return convertStixMetaRelationshipToStix(data, eventExtraData);
  }
  throw FunctionalError(`The converter is not able to convert this type of entity: ${entityType}`);
};
