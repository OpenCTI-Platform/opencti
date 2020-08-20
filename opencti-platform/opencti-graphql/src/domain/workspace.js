import { assoc, concat, map, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationsByFromAndTo,
  escapeString,
  executeWrite,
  getSingleValueNumber,
  listEntities,
  load,
  loadEntityById,
  prepareDate,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { findAll as findAllStixDomains } from './workspace';
import { FunctionalError } from '../config/errors';
import {
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ENTITY_TYPE_WORKSPACE,
  isInternalRelationship,
  isStixMetaRelationship,
  RELATION_OBJECT,
} from '../utils/idGenerator';

// region grakn fetch
export const findById = (workspaceId) => {
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_WORKSPACE], ['name', 'description'], args);
};

export const ownedBy = async (workspaceId) => {
  const element = await load(
    `match $x isa User; $rel(owner:$x, so:$workspace) isa owned_by; 
    $workspace has internal_id "${escapeString(workspaceId)}"; get;`,
    ['x']
  );
  return element && element.x;
};

export const objectRefs = (workspaceId, args) => {
  const filter = { key: `${RELATION_OBJECT}.internal_id`, values: [workspaceId] };
  const filters = concat([filter], args.filters || []);
  const finalArgs = pipe(assoc('filters', filters), assoc('types', ['Stix-Domain-Object']))(args);
  return findAllStixDomains(finalArgs);
};
// endregion

// region time series
export const workspacesNumber = (args) => {
  return {
    count: getSingleValueNumber(
      `match $x isa ${ENTITY_TYPE_WORKSPACE}; ${
        args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
      } get; count;`
    ),
    total: getSingleValueNumber(`match $x isa ${ENTITY_TYPE_WORKSPACE}; get; count;`),
  };
};
// endregion

// region mutations
export const addWorkspace = async (user, workspace) => {
  const created = await createEntity(user, workspace, ENTITY_TYPE_WORKSPACE, {
    noLog: true,
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};

export const workspaceDelete = (user, workspaceId) =>
  deleteEntityById(user, workspaceId, ENTITY_TYPE_WORKSPACE, { noLog: true });

export const workspaceAddRelation = async (user, workspaceId, input) => {
  const workspace = await loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError(`Cannot add the relation, ${ENTITY_TYPE_WORKSPACE} cannot be found.`);
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = assoc('fromId', workspaceId, input);
  return createRelation(user, finalInput).then((relationData) => {
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, relationData, user);
    return relationData;
  });
};

export const workspaceAddRelations = async (user, workspaceId, input) => {
  const workspace = await loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot add the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isInternalRelationship(input.relationship_type)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be added through this method.`);
  }
  const finalInput = map(
    (n) => ({ fromId: workspaceId, toId: n, relationship_type: input.relationship_type }),
    input.toIds
  );
  await createRelations(user, finalInput);
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE).then((entity) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, entity, user)
  );
};

export const workspaceDeleteRelation = async (user, workspaceId, toId, relationshipType) => {
  const workspace = await loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
  if (!workspace) {
    throw FunctionalError('Cannot delete the relation, Stix-Domain-Object cannot be found.');
  }
  if (!isStixMetaRelationship(relationshipType)) {
    throw FunctionalError(`Only ${ABSTRACT_INTERNAL_RELATIONSHIP} can be deleted through this method.`);
  }
  await deleteRelationsByFromAndTo(user, workspaceId, toId, relationshipType, ABSTRACT_INTERNAL_RELATIONSHIP);
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
};

export const workspaceEditField = (user, workspaceId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, workspaceId, ENTITY_TYPE_WORKSPACE, input, wTx, { noLog: true });
  }).then(async () => {
    const workspace = await loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
    return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user);
  });
};
// endregion

// region context
export const workspaceCleanContext = (user, workspaceId) => {
  delEditContext(user, workspaceId);
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE).then((workspace) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user)
  );
};

export const workspaceEditContext = (user, workspaceId, input) => {
  setEditContext(user, workspaceId, input);
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE).then((workspace) =>
    notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].EDIT_TOPIC, workspace, user)
  );
};
// endregion
