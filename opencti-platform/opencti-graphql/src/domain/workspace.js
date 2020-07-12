import { assoc, concat, map, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createEntity,
  createRelation,
  createRelations,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  getSingleValueNumber,
  listEntities,
  loadEntityById,
  loadWithConnectedRelations,
  prepareDate,
  updateAttribute,
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { findAll as findAllStixDomains } from './stixDomainEntity';
import { ForbiddenAccess } from '../config/errors';
import { ENTITY_TYPE_WORKSPACE, RELATION_OBJECT } from '../utils/idGenerator';

// region grakn fetch
export const findById = (workspaceId) => {
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
};
export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_WORKSPACE], ['name', 'description'], args);
};
export const ownedBy = (workspaceId) => {
  return loadWithConnectedRelations(
    `match $x isa User; 
    $rel(owner:$x, so:$workspace) isa owned_by; 
    $workspace has internal_id_key "${escapeString(workspaceId)}"; get; offset 0; limit 1;`,
    'x',
    { extraRelKey: 'rel' }
  );
};
export const objectRefs = (workspaceId, args) => {
  const filter = { key: `${RELATION_OBJECT}.internal_id_key`, values: [workspaceId] };
  const filters = concat([filter], args.filters || []);
  const finalArgs = pipe(assoc('filters', filters), assoc('types', ['Stix-Domain-Entity']))(args);
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
  const workspaceToCreate = assoc('createdByOwner', user.id, workspace);
  const created = await createEntity(user, workspaceToCreate, ENTITY_TYPE_WORKSPACE, {
    noLog: true,
  });
  return notify(BUS_TOPICS.Workspace.ADDED_TOPIC, created, user);
};
export const workspaceDelete = (user, workspaceId) =>
  deleteEntityById(user, workspaceId, ENTITY_TYPE_WORKSPACE, { noLog: true });
export const workspaceAddRelation = (user, workspaceId, input) => {
  if (!input.through) throw ForbiddenAccess();
  const finalInput = pipe(assoc('fromId', workspaceId), assoc('fromType', ENTITY_TYPE_WORKSPACE))(input);
  return createRelation(user, finalInput, { noLog: true }).then((relationData) => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const workspaceAddRelations = async (user, workspaceId, input) => {
  if (!input.through) {
    throw ForbiddenAccess();
  }
  const finalInputs = map(
    (n) => ({
      fromType: ENTITY_TYPE_WORKSPACE,
      fromRole: input.fromRole,
      toId: n,
      toRole: input.toRole,
      through: input.through,
    }),
    input.toIds
  );
  await createRelations(user, workspaceId, finalInputs);
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE).then((workspace) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};
export const workspaceEditField = (user, workspaceId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, workspaceId, ENTITY_TYPE_WORKSPACE, input, wTx, { noLog: true });
  }).then(async () => {
    const workspace = await loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
    return notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user);
  });
};
export const workspaceDeleteRelation = async (user, workspaceId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation');
  const data = await loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE);
  return notify(BUS_TOPICS.Workspace.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const workspaceCleanContext = (user, workspaceId) => {
  delEditContext(user, workspaceId);
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE).then((workspace) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};
export const workspaceEditContext = (user, workspaceId, input) => {
  setEditContext(user, workspaceId, input);
  return loadEntityById(workspaceId, ENTITY_TYPE_WORKSPACE).then((workspace) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};
// endregion
