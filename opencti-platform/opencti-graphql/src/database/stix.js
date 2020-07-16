import { assoc, dissoc, pick, map, isNil, pipe } from 'ramda';
import { FunctionalError } from '../config/errors';
import {
  RELATION_CREATED_BY,
  isStixObject,
  isStixCoreRelationship,
  isStixMetaRelationship,
  isStixSightingRelationship,
  isStixInternalMetaRelationship,
} from '../utils/idGenerator';

export const STIX_SPEC_VERSION = '2.1';

export const buildStixData = (entityData, onlyBase = false) => {
  const finalData = pipe(
    dissoc('standard_stix_id'),
    dissoc('internal_id'),
    assoc('id', entityData.standard_stix_id),
    dissoc('entity_type'),
    assoc('type', entityData.entity_type.toLowerCase()),
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

export const labelsToStix = (labelsEdges) => map((label) => label.node.standard_stix_id, labelsEdges);

export const externalReferencesToStix = (externalReferencesEdges) =>
  map(
    (externalReference) =>
      buildStixData({}, externalReference.node, { source_name: 'source_name', external_id: 'external_id', url: 'url' }),
    externalReferencesEdges
  );

export const killChainPhasesToStix = (killChainPhasesEdges) =>
  map(
    (killChainPhase) =>
      buildStixData({}, killChainPhase.node, { kill_chain_name: 'kill_chain_name', phase_name: 'phase_name' }),
    killChainPhasesEdges
  );

export const objectsToStix = (objectRefsEdges) => map((objectRef) => objectRef.node.standard_stix_id, objectRefsEdges);

export const markingDefinitionToStix = (markingDefinition, onlyBase = false) => {
  const baseData = {
    id: markingDefinition.standard_stix_id,
    type: 'marking-definition',
    spec_version: STIX_SPEC_VERSION,
  };
  if (onlyBase) {
    return baseData;
  }
  return buildStixData(baseData, markingDefinition, {
    definition_type: 'definition_type',
    definition: 'definition',
    stix_label: 'labels',
    revoked: 'revoked',
    created: 'created',
    modified: 'x_opencti_modified',
  });
};

const convertStixObjectToStix = (data, onlyBase) => {
  const finalData = pipe(
    dissoc('standard_stix_id'),
    dissoc('internal_id'),
    assoc('id', data.standard_stix_id),
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

export const convertStixCoreRelationshipToStix = (data, extra = null, onlyBase = true) => {
  const finalData = pipe(
    dissoc('standard_stix_id'),
    dissoc('internal_id'),
    assoc('id', data.standard_stix_id),
    dissoc('entity_type'),
    assoc('type', 'relationship'),
    // Relation IDs
    assoc('source_ref', extra.from.standard_stix_id),
    assoc('target_ref', extra.to.standard_stix_id)
  )(data);
  if (onlyBase) {
    return pick(['id', 'type', 'spec_version'], data);
  }
  return finalData;
};

export const convertStixSightingRelationshipToStix = async (data, extra = null, onlyBase = true) => {
  const finalData = pipe(
    dissoc('standard_stix_id'),
    dissoc('internal_id'),
    assoc('id', data.standard_stix_id),
    dissoc('entity_type'),
    assoc('type', 'relationship'),
    // Reserved keywords in Grakn
    dissoc('attribute_count'),
    assoc('count', data.attribute_count),
    // Relation IDs
    assoc('sighting_of_ref', extra.from.standard_stix_id),
    assoc('where_sighted_refs', [extra.to.standard_stix_id])
  )(data);
  if (onlyBase) {
    return pick(['id', 'type', 'spec_version'], data);
  }
  return finalData;
};

export const convertStixMetaRelationshipToStix = (data, eventType, extra) => {
  const entityType = data.entity_type;
  let finalData = convertStixObjectToStix(extra.from, true);
  if (isStixInternalMetaRelationship(entityType)) {
    // Internal Meta = _ref or _refs
    finalData = assoc(
      `${entityType.replace('-', '_')}_ref${data.entity_type !== RELATION_CREATED_BY ? 's' : ''}`,
      isNil(extra.to) ? null : extra.to.standard_stix_id,
      finalData
    );
  } else {
    finalData = assoc(`${entityType.replace('-', '_')}s`, [convertStixObjectToStix(extra.to)], finalData);
  }
  return finalData;
};

export const convertDataToStix = async (data, eventType = null, eventExtraData = null) => {
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
    return convertStixMetaRelationshipToStix(data, eventExtraData, onlyBase);
  }
  throw FunctionalError(`The converter is not able to convert this type of entity: ${entityType}`);
};
