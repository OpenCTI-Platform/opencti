import { assoc, dissoc, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  batchListThroughGetFrom,
  batchListThroughGetTo,
  batchLoadThroughGetTo,
  createRelation,
  deleteElementById,
  updateAttribute,
} from '../database/middleware';
import { BUS_TOPICS } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
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
import { elCount } from '../database/engine';
import { READ_INDEX_STIX_SIGHTING_RELATIONSHIPS } from '../database/utils';
import { listRelations, storeLoadById } from '../database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { stixObjectOrRelationshipDeleteRelation } from './stixObjectOrStixRelationship';

export const findAll = async (context, user, args) => {
  return listRelations(context, user, STIX_SIGHTING_RELATIONSHIP, args);
};

export const findById = (context, user, stixSightingRelationshipId) => {
  return storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};

export const stixSightingRelationshipsNumber = (context, user, args) => ({
  count: elCount(context, user, READ_INDEX_STIX_SIGHTING_RELATIONSHIPS, assoc('types', [STIX_SIGHTING_RELATIONSHIP], args)),
  total: elCount(
    context,
    user,
    READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
    pipe(assoc('types', [STIX_SIGHTING_RELATIONSHIP]), dissoc('endDate'))(args)
  ),
});

export const batchCreatedBy = async (context, user, stixCoreRelationshipIds) => {
  return batchLoadThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_CREATED_BY, ENTITY_TYPE_IDENTITY);
};

export const batchReports = async (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_REPORT);
};

export const batchCases = async (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_CASE);
};

export const batchNotes = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_NOTE);
};

export const batchOpinions = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetFrom(context, user, stixCoreRelationshipIds, RELATION_OBJECT, ENTITY_TYPE_CONTAINER_OPINION);
};

export const batchLabels = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_OBJECT_LABEL, ENTITY_TYPE_LABEL);
};

export const batchMarkingDefinitions = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(context, user, stixCoreRelationshipIds, RELATION_OBJECT_MARKING, ENTITY_TYPE_MARKING_DEFINITION);
};

export const batchExternalReferences = (context, user, stixCoreRelationshipIds) => {
  return batchListThroughGetTo(
    context,
    user,
    stixCoreRelationshipIds,
    RELATION_EXTERNAL_REFERENCE,
    ENTITY_TYPE_EXTERNAL_REFERENCE
  );
};

// region mutations
export const addStixSightingRelationship = async (context, user, stixSightingRelationship) => {
  const created = await createRelation(
    context,
    user,
    assoc('relationship_type', STIX_SIGHTING_RELATIONSHIP, stixSightingRelationship)
  );
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].ADDED_TOPIC, created, user);
};
export const stixSightingRelationshipDelete = async (context, user, stixSightingRelationshipId) => {
  return deleteElementById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
};
export const stixSightingRelationshipEditField = async (context, user, relationshipId, input, opts) => {
  const { element } = await updateAttribute(context, user, relationshipId, STIX_SIGHTING_RELATIONSHIP, input, opts);
  return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, element, user);
};
export const stixSightingRelationshipAddRelation = async (context, user, stixSightingRelationshipId, input) => {
  const stixSightingRelationship = await storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP);
  if (!stixSightingRelationship) {
    throw FunctionalError(`Cannot add the relation, ${ABSTRACT_STIX_META_RELATIONSHIP} cannot be found.`);
  }
  if (!isStixMetaRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_STIX_META_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('fromId', stixSightingRelationshipId, input);
  return createRelation(context, user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const stixSightingRelationshipDeleteRelation = async (context, user, stixSightingRelationshipId, toId, relationshipType) => {
  return stixObjectOrRelationshipDeleteRelation(context, user, stixSightingRelationshipId, toId, relationshipType, STIX_SIGHTING_RELATIONSHIP);
};
// endregion

// region context
export const stixSightingRelationshipCleanContext = (context, user, stixSightingRelationshipId) => {
  delEditContext(user, stixSightingRelationshipId);
  return storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP).then((stixSightingRelationship) => {
    return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user);
  });
};
export const stixSightingRelationshipEditContext = (context, user, stixSightingRelationshipId, input) => {
  setEditContext(user, stixSightingRelationshipId, input);
  return storeLoadById(context, user, stixSightingRelationshipId, STIX_SIGHTING_RELATIONSHIP).then((stixSightingRelationship) => {
    return notify(BUS_TOPICS[STIX_SIGHTING_RELATIONSHIP].EDIT_TOPIC, stixSightingRelationship, user);
  });
};
// endregion
