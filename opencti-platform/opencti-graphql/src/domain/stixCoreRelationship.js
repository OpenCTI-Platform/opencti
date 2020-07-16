import { assoc, dissoc, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteRelationById,
  escapeString,
  executeWrite,
  findWithConnectedRelations,
  getRelationInferredById,
  internalLoadEntityById,
  listRelations,
  loadRelationById,
  loadWithConnectedRelations,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { elCount } from '../database/elasticSearch';
import { buildPagination, INDEX_STIX_RELATIONS } from '../database/utils';
import {
  isStixId,
  isInternalId,
  isStixCoreRelationship,
  RELATION_CREATED_BY,
  RELATION_OBJECT,
  ENTITY_TYPE_LABEL,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_EXTERNAL_REFERENCE,
} from '../utils/idGenerator';

export const findAll = async (args) => {
  return listRelations(propOr('stix_relation', 'relationType', args), args);
};
export const findById = (stixCoreRelationshipId) => {
  if (!isStixId(stixCoreRelationshipId) && !isInternalId(stixCoreRelationshipId)) {
    return getRelationInferredById(stixCoreRelationshipId);
  }
  return loadRelationById(stixCoreRelationshipId, 'stix_relation');
};

export const stixCoreRelationshipsNumber = (args) => {
  let finalArgs;
  if (args.type && args.type !== 'stix_relation' && args.type !== 'stix_relation_embedded') {
    finalArgs = assoc('relationshipType', args.type, args);
  } else {
    finalArgs = args.type ? assoc('types', [args.type], args) : assoc('types', ['stix_relation'], args);
  }
  return {
    count: elCount(INDEX_STIX_RELATIONS, finalArgs),
    total: elCount(INDEX_STIX_RELATIONS, dissoc('endDate', finalArgs)),
  };
};

export const createdBy = (stixCoreObjectId) => {
  return loadWithConnectedRelations(
    `match $to isa Identity; $rel(creator:$to, so:$from) isa ${RELATION_CREATED_BY};
   $from has internal_id "${escapeString(stixCoreObjectId)}"; get; offset 0; limit 1;`,
    'to',
    { extraRelKey: 'rel' }
  );
};
export const reports = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Report; $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
   $from has internal_id "${escapeString(stixCoreObjectId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const notes = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Note; $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
   $from has internal_id "${escapeString(stixCoreObjectId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const opinions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Opinion; $rel(knowledge_aggregation:$to, so:$from) isa ${RELATION_OBJECT};
   $from has internal_id "${escapeString(stixCoreObjectId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const labels = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa ${ENTITY_TYPE_LABEL}; $rel(tagging:$to, so:$from) isa ${RELATION_OBJECT_LABEL};
   $from has internal_id "${escapeString(stixCoreObjectId)}";
   get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const markingDefinitions = (stixCoreObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Marking-Definition; $rel(marking:$to, so:$from) isa ${RELATION_OBJECT_MARKING};
   $from has internal_id "${escapeString(stixCoreObjectId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const killChainPhases = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa Kill-Chain-Phase; $rel(kill_chain_phase:$to, phase_belonging:$from) isa ${RELATION_KILL_CHAIN_PHASE};
    $from has internal_id "${escapeString(stixDomainObjectId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};
export const externalReferences = (stixDomainObjectId) => {
  return findWithConnectedRelations(
    `match $to isa External-Reference; $rel(external_reference:$to, so:$from) isa ${RELATION_EXTERNAL_REFERENCE};
    $from has internal_id "${escapeString(stixDomainObjectId)}"; get;`,
    'to',
    { extraRelKey: 'rel' }
  ).then((data) => buildPagination(0, 0, data, data.length));
};

export const stixRelations = (stixCoreObjectId, args) => {
  const finalArgs = assoc('fromId', stixCoreObjectId, args);
  return relationFindAll(finalArgs);
};

// region mutations
export const addStixCoreRelationship = async (user, stixCoreRelationship, reversedReturn = false) => {
  // We force the created by ref if not specified
  let input = stixCoreRelationship;
  if (!stixCoreRelationship.createdBy) {
    input = assoc('createdBy', user.id, stixCoreRelationship);
  }
  const created = await createRelation(user, input, { reversedReturn });
  return notify(BUS_TOPICS.StixCoreRelationship.ADDED_TOPIC, created, user);
};
export const stixCoreRelationshipDelete = async (user, stixCoreRelationshipId) => {
  return deleteRelationById(user, stixCoreRelationshipId, 'stix_relation');
};
export const stixCoreRelationshipEditField = (user, stixCoreRelationshipId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, stixCoreRelationshipId, 'stix_relation', input, wTx);
  }).then(async () => {
    const stixCoreRelationship = await loadRelationById(stixCoreRelationshipId, 'stix_relation');
    return notify(BUS_TOPICS.StixCoreRelationship.EDIT_TOPIC, stixCoreRelationship, user);
  });
};
export const stixCoreRelationshipAddRelation = async (user, stixCoreRelationshipId, input) => {
  const data = await internalLoadEntityById(stixCoreRelationshipId);
  if (!isStixCoreRelationship(data.type) || !input.relationship_type) {
    throw ForbiddenAccess();
  }
  const finalInput = assoc('fromId', stixCoreRelationshipId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS.StixCoreRelationship.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixCoreRelationshipDeleteRelation = async (user, stixCoreRelationshipId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation_embedded');
  const data = await loadRelationById(stixCoreRelationshipId, 'stix_relation');
  return notify(BUS_TOPICS.StixCoreRelationship.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const stixCoreRelationshipCleanContext = (user, stixCoreRelationshipId) => {
  delEditContext(user, stixCoreRelationshipId);
  return loadRelationById(stixCoreRelationshipId, 'stix_relation').then((stixCoreRelationship) =>
    notify(BUS_TOPICS.StixCoreRelationship.EDIT_TOPIC, stixCoreRelationship, user)
  );
};

export const stixCoreRelationshipEditContext = (user, stixCoreRelationshipId, input) => {
  setEditContext(user, stixCoreRelationshipId, input);
  return loadRelationById(stixCoreRelationshipId, 'stix_relation').then((stixCoreRelationship) =>
    notify(BUS_TOPICS.StixCoreRelationship.EDIT_TOPIC, stixCoreRelationship, user)
  );
};
// endregion
