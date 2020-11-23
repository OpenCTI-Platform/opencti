import { assoc, dissoc, propOr } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  escapeString,
  getRelationInferredById,
  listFromEntitiesThroughRelation,
  listRelations,
  listToEntitiesThroughRelation,
  load,
  loadById,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { elCount } from '../database/elasticSearch';
import { INDEX_STIX_CORE_RELATIONSHIPS } from '../database/utils';
import { isAnId } from '../schema/schemaUtils';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ENTITY_TYPE_IDENTITY,
} from '../schema/general';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from '../schema/stixMetaRelationship';
import {
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
} from '../schema/stixDomainObject';
import {
  ENTITY_TYPE_EXTERNAL_REFERENCE,
  ENTITY_TYPE_KILL_CHAIN_PHASE,
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';

export const findAll = async (args) =>
  listRelations(propOr(ABSTRACT_STIX_CORE_RELATIONSHIP, 'relationship_type', args), args);

export const findById = (stixCoreRelationshipId) => {
  if (!isAnId(stixCoreRelationshipId)) {
    return getRelationInferredById(stixCoreRelationshipId);
  }
  return loadById(stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

export const stixCoreRelationshipsNumber = (args) => {
  const types = [];
  if (args.type) {
    if (isStixCoreRelationship(args.type)) {
      types.push(args.type);
    }
  }
  if (types.length === 0) {
    types.push(ABSTRACT_STIX_CORE_RELATIONSHIP);
  }
  const finalArgs = assoc('types', types, args);
  return {
    count: elCount(INDEX_STIX_CORE_RELATIONSHIPS, finalArgs),
    total: elCount(INDEX_STIX_CORE_RELATIONSHIPS, dissoc('endDate', finalArgs)),
  };
};

export const createdBy = async (stixCoreRelationshipId) => {
  const element = await load(
    `match $to isa ${ENTITY_TYPE_IDENTITY}; 
    $rel(${RELATION_CREATED_BY}_from:$from, ${RELATION_CREATED_BY}_to: $to) isa ${RELATION_CREATED_BY};
    $from has internal_id "${escapeString(stixCoreRelationshipId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

export const reports = (stixCoreRelationshipId) => {
  return listFromEntitiesThroughRelation(stixCoreRelationshipId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const notes = (stixCoreRelationshipId) => {
  return listFromEntitiesThroughRelation(stixCoreRelationshipId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const opinions = (stixCoreRelationshipId) => {
  return listFromEntitiesThroughRelation(stixCoreRelationshipId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

export const labels = (stixCoreRelationshipId) => {
  return listToEntitiesThroughRelation(stixCoreRelationshipId, null, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const markingDefinitions = (stixCoreRelationshipId) => {
  return listToEntitiesThroughRelation(
    stixCoreRelationshipId,
    null,
    RELATION_OBJECT_MARKING,
    ENTITY_TYPE_MARKING_DEFINITION
  );
};

export const killChainPhases = (stixCoreRelationshipId) => {
  return listToEntitiesThroughRelation(
    stixCoreRelationshipId,
    null,
    RELATION_KILL_CHAIN_PHASE,
    ENTITY_TYPE_KILL_CHAIN_PHASE
  );
};

export const externalReferences = (stixCoreRelationshipId) => {
  return listToEntitiesThroughRelation(
    stixCoreRelationshipId,
    null,
    RELATION_EXTERNAL_REFERENCE,
    ENTITY_TYPE_EXTERNAL_REFERENCE
  );
};

export const stixRelations = (stixCoreObjectId, args) => {
  const finalArgs = assoc('fromId', stixCoreObjectId, args);
  return findAll(finalArgs);
};

// region mutations
export const addStixCoreRelationship = async (user, stixCoreRelationship) => {
  if (!isStixCoreRelationship(stixCoreRelationship.relationship_type)) {
    throw FunctionalError('Only stix-core-relationship can be created trough this method.');
  }
  const created = await createRelation(user, stixCoreRelationship);
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].ADDED_TOPIC, created, user);
};

export const stixCoreRelationshipDelete = async (user, stixCoreRelationshipId) => {
  return deleteElementById(user, stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
};

export const stixCoreRelationshipDeleteByFromAndTo = async (user, fromId, toId, relationshipType) => {
  if (!isStixCoreRelationship(relationshipType)) {
    throw FunctionalError('Only stix-core-relationship can be deleted trough this method.');
  }
  await deleteRelationsByFromAndTo(user, fromId, toId, relationshipType, ABSTRACT_STIX_CORE_RELATIONSHIP);
  return true;
};

export const stixCoreRelationshipEditField = async (user, stixCoreRelationshipId, input) => {
  const stixCoreRelationship = await loadById(stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot edit the field, stix-core-relationship cannot be found.');
  }
  const updatedRelationship = await updateAttribute(
    user,
    stixCoreRelationshipId,
    ABSTRACT_STIX_CORE_RELATIONSHIP,
    input
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, updatedRelationship, user);
};

export const stixCoreRelationshipAddRelation = async (user, stixCoreRelationshipId, input) => {
  const stixCoreRelationship = await loadById(stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError('Cannot add the relation, stix-core-relationship cannot be found.');
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('fromId', stixCoreRelationshipId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixCoreRelationshipDeleteRelation = async (user, stixCoreRelationshipId, toId, relationshipType) => {
  const stixCoreRelationship = await loadById(stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP);
  if (!stixCoreRelationship) {
    throw FunctionalError(`Cannot delete the relation, ${ABSTRACT_STIX_CORE_RELATIONSHIP} cannot be found.`);
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
    user,
    stixCoreRelationshipId,
    toId,
    relationshipType,
    ABSTRACT_STIX_META_RELATIONSHIP
  );
  return notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user);
};
// endregion

// region context
export const stixCoreRelationshipCleanContext = (user, stixCoreRelationshipId) => {
  delEditContext(user, stixCoreRelationshipId);
  return loadById(stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP).then((stixCoreRelationship) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user)
  );
};

export const stixCoreRelationshipEditContext = (user, stixCoreRelationshipId, input) => {
  setEditContext(user, stixCoreRelationshipId, input);
  return loadById(stixCoreRelationshipId, ABSTRACT_STIX_CORE_RELATIONSHIP).then((stixCoreRelationship) =>
    notify(BUS_TOPICS[ABSTRACT_STIX_CORE_RELATIONSHIP].EDIT_TOPIC, stixCoreRelationship, user)
  );
};
// endregion
