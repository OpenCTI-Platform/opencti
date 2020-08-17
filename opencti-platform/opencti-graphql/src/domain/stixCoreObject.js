import { assoc, filter } from 'ramda';
import {
  createRelation,
  deleteRelationsByFromAndTo,
  escapeString,
  findWithConnectedRelations,
  internalLoadEntityById,
  listEntities,
  listFromEntitiesThroughRelation,
  listToEntitiesThroughRelation,
  load,
  loadEntityById,
} from '../database/grakn';
import { findAll as relationFindAll } from './stixCoreRelationship';
import { buildPagination } from '../database/utils';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess, FunctionalError } from '../config/errors';
import {
  isStixCoreObject,
  isStixRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT,
  RELATION_OBJECT_MARKING,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_MARKING_DEFINITION,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  isStixMetaRelationship,
  ABSTRACT_STIX_META_RELATIONSHIP,
} from '../utils/idGenerator';

export const findAll = async (args) => {
  let types = [];
  if (args.types && args.types.length > 0) {
    types = filter((type) => isStixCoreObject(type), args.types);
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_OBJECT);
  }
  return listEntities(types, ['standard_id'], args);
};

export const findById = async (stixCoreObjectId) => loadEntityById(stixCoreObjectId, ABSTRACT_STIX_CORE_OBJECT);

export const createdBy = async (stixCoreObjectId) => {
  const element = await load(
    `match $to isa ${ENTITY_TYPE_IDENTITY};
    $rel(${RELATION_CREATED_BY}_from:$from, ${RELATION_CREATED_BY}_to: $to) isa ${RELATION_CREATED_BY};
    $from has internal_id "${escapeString(stixCoreObjectId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

export const reports = async (stixCoreObjectId) => {
  const rel = { from: RELATION_OBJECT, to: RELATION_OBJECT, type: RELATION_OBJECT };
  return listFromEntitiesThroughRelation(stixCoreObjectId, rel, ENTITY_TYPE_CONTAINER_REPORT);
};

export const notes = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_NOTE}; 
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT};
    $to has internal_id "${escapeString(stixCoreObjectId)}"; get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const opinions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $from isa ${ENTITY_TYPE_CONTAINER_OPINION};
    $rel(${RELATION_OBJECT}_from:$from, ${RELATION_OBJECT}_to:$to) isa ${RELATION_OBJECT};
    $to has internal_id "${escapeString(stixCoreObjectId)}"; get;`,
    'from',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const labels = async (stixCoreObjectId) => {
  const rel = { from: RELATION_OBJECT_LABEL, to: RELATION_OBJECT_LABEL, type: RELATION_OBJECT_LABEL };
  return listToEntitiesThroughRelation(stixCoreObjectId, rel, ENTITY_TYPE_LABEL);
};

export const markingDefinitions = (stixCoreObjectId) => {
  const rel = { from: RELATION_OBJECT_MARKING, to: RELATION_OBJECT_MARKING, type: RELATION_OBJECT_MARKING };
  return listToEntitiesThroughRelation(stixCoreObjectId, rel, ENTITY_TYPE_MARKING_DEFINITION);
};

export const killChainPhases = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_KILL_CHAIN_PHASE};
    $rel(${RELATION_KILL_CHAIN_PHASE}_from:$from, ${RELATION_KILL_CHAIN_PHASE}_to:$to) isa ${RELATION_KILL_CHAIN_PHASE};
    $from has internal_id "${escapeString(stixDomainObjectId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const externalReferences = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_EXTERNAL_REFERENCE}, has internal_id $to_id;
    $rel(${RELATION_EXTERNAL_REFERENCE}_from:$from, ${RELATION_EXTERNAL_REFERENCE}_to:$to) isa ${RELATION_EXTERNAL_REFERENCE}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    $from has internal_id "${escapeString(stixDomainObjectId)}";
    get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const stixCoreRelationships = (stixCoreObjectId, args) => {
  const finalArgs = assoc('fromId', stixCoreObjectId, args);
  return relationFindAll(finalArgs);
};

export const stixCoreObjectAddRelation = async (user, stixCoreObjectId, input) => {
  const data = await internalLoadEntityById(stixCoreObjectId);
  if (!isStixCoreObject(data.type) || !isStixRelationship(input.relationship_type)) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixCoreObjectId, input);
  return createRelation(user, finalInput);
};

export const stixCoreObjectDeleteRelation = async (user, stixCoreObjectId, toId, relationshipType) => {
  const stixCoreObject = await loadEntityById(stixCoreObjectId, ABSTRACT_STIX_DOMAIN_OBJECT);
  if (!stixCoreObject) {
    throw FunctionalError('Cannot delete the relation, Stix-Core-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, stixCoreObjectId, toId, relationshipType, ABSTRACT_STIX_META_RELATIONSHIP);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_OBJECT].EDIT_TOPIC, stixCoreObjectId, user);
};
