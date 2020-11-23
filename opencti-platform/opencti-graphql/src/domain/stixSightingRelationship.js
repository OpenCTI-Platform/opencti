import { assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteElementById,
  deleteRelationsByFromAndTo,
  escapeString,
  getRelationInferredById,
  getSingleValueNumber,
  listFromEntitiesThroughRelation,
  listRelations,
  listToEntitiesThroughRelation,
  load,
  loadById,
  prepareDate,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { isAnId } from '../schema/schemaUtils';
import { ABSTRACT_STIX_META_RELATIONSHIP, ENTITY_TYPE_IDENTITY } from '../schema/general';
import {
  isStixMetaRelationship,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
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
  ENTITY_TYPE_LABEL,
  ENTITY_TYPE_MARKING_DEFINITION,
} from '../schema/stixMetaObject';

export const findAll = async (args) => {
  return listRelations(STIX_SIGHTING_RELATIONSHIP, args);
};
export const findById = (stixSightingRelationshipId) => {
  if (!isAnId(stixSightingRelationshipId)) {
    return getRelationInferredById(stixSightingRelationshipId);
  }
  return loadById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};

export const stixSightingRelationshipsNumber = (args) => ({
  count: getSingleValueNumber(
    `match $x($y, $z) isa ${STIX_SIGHTING_RELATIONSHIP}; ${
      args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
    } ${args.fromId ? `$y has internal_id "${escapeString(args.fromId)}";` : ''} get; count;`,
    args.inferred ? args.inferred : false
  ),
  total: getSingleValueNumber(
    `match $x($y, $z) isa ${STIX_SIGHTING_RELATIONSHIP}; ${
      args.fromId ? `$y has internal_id "${escapeString(args.fromId)}";` : ''
    } get; count;`,
    args.inferred ? args.inferred : false
  ),
});

export const createdBy = async (stixSightingRelationshipId) => {
  const element = await load(
    `match $to isa ${ENTITY_TYPE_IDENTITY}; 
    $rel(${RELATION_CREATED_BY}_from:$from, ${RELATION_CREATED_BY}_to: $to) isa ${RELATION_CREATED_BY};
    $from has internal_id "${escapeString(stixSightingRelationshipId)}"; get;`,
    ['to']
  );
  return element && element.to;
};

export const reports = (stixSightingRelationshipId) => {
  return listFromEntitiesThroughRelation(
    stixSightingRelationshipId,
    null,
    RELATION_OBJECT,
    ENTITY_TYPE_CONTAINER_REPORT
  );
};

export const notes = (stixSightingRelationshipId) => {
  return listFromEntitiesThroughRelation(stixSightingRelationshipId, null, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const opinions = (stixSightingRelationshipId) => {
  return listFromEntitiesThroughRelation(
    stixSightingRelationshipId,
    null,
    RELATION_OBJECT,
    ENTITY_TYPE_CONTAINER_OPINION
  );
};

export const labels = (stixSightingRelationshipId) => {
  return listToEntitiesThroughRelation(stixSightingRelationshipId, null, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const markingDefinitions = (stixSightingRelationshipId) => {
  return listToEntitiesThroughRelation(
    stixSightingRelationshipId,
    null,
    RELATION_OBJECT_MARKING,
    ENTITY_TYPE_MARKING_DEFINITION
  );
};

export const externalReferences = (stixSightingRelationshipId) => {
  return listToEntitiesThroughRelation(
    stixSightingRelationshipId,
    null,
    RELATION_EXTERNAL_REFERENCE,
    ENTITY_TYPE_EXTERNAL_REFERENCE
  );
};

// region mutations
export const addStixSightingRelationship = async (user, stixSightingRelationship) => {
  const created = await createRelation(
    user,
    assoc('relationship_type', STIX_SIGHTING_RELATIONSHIP, stixSightingRelationship)
  );
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].ADDED_TOPIC, created, user);
};
export const stixSightingRelationshipDelete = async (user, stixSightingRelationshipId) => {
  return deleteElementById(user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};
export const stixSightingRelationshipEditField = async (user, relationshipId, input) => {
  const stixSightingRelationship = await updateAttribute(user, relationshipId, STIX_SIGHTING_RELATIONSHIP, input);
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user);
};
export const stixSightingRelationshipAddRelation = async (user, stixSightingRelationshipId, input) => {
  const stixSightingRelationship = await loadById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  if (!stixSightingRelationship) {
    throw FunctionalError(`Cannot add the relation, ${ABSTRACT_STIX_META_RELATIONSHIP} cannot be found.`);
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('fromId', stixSightingRelationshipId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const stixSightingRelationshipDeleteRelation = async (
  user,
  stixSightingRelationshipId,
  toId,
  relationshipType
) => {
  const stixSightingRelationship = await loadById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  if (!stixSightingRelationship) {
    throw FunctionalError(`Cannot delete the relation, ${STIX_SIGHTING_RELATIONSHIP} cannot be found.`);
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(
    user,
    stixSightingRelationshipId,
    toId,
    relationshipType,
    ABSTRACT_STIX_META_RELATIONSHIP
  );
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user);
};
// endregion

// region context
export const stixSightingRelationshipCleanContext = (user, stixSightingRelationshipId) => {
  delEditContext(user, stixSightingRelationshipId);
  return loadById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP).then((stixSightingRelationship) =>
    notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user)
  );
};
export const stixSightingRelationshipEditContext = (user, stixSightingRelationshipId, input) => {
  setEditContext(user, stixSightingRelationshipId, input);
  return loadById(stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP).then((stixSightingRelationship) =>
    notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user)
  );
};
// endregion
