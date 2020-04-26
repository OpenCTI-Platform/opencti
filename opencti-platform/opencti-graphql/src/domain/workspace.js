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
import { TYPE_OPENCTI_INTERNAL } from '../database/utils';

// region grakn fetch
export const findById = (workspaceId) => {
  return loadEntityById(workspaceId, 'Workspace');
};
export const findAll = (args) => {
  return listEntities(['Workspace'], ['name', 'description'], args);
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
  const filter = { key: 'object_refs.internal_id_key', values: [workspaceId] };
  const filters = concat([filter], args.filters || []);
  const finalArgs = pipe(assoc('filters', filters), assoc('types', ['Stix-Domain-Entity']))(args);
  return findAllStixDomains(finalArgs);
};
// endregion

// region time series
export const workspacesNumber = (args) => {
  return {
    count: getSingleValueNumber(
      `match $x isa Workspace; ${
        args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
      } get; count;`
    ),
    total: getSingleValueNumber(`match $x isa Workspace; get; count;`),
  };
};
// endregion

// region mutations
export const addWorkspace = async (user, workspace) => {
  const workspaceToCreate = assoc('createdByOwner', user.id, workspace);
  const created = await createEntity(user, workspaceToCreate, 'Workspace', {
    modelType: TYPE_OPENCTI_INTERNAL,
    noLog: true,
  });
  return notify(BUS_TOPICS.Workspace.ADDED_TOPIC, created, user);
};
export const workspaceDelete = (user, workspaceId) => deleteEntityById(user, workspaceId, 'Workspace', { noLog: true });
export const workspaceAddRelation = (user, workspaceId, input) => {
  if (!input.through) {
    throw new ForbiddenAccess();
  }
  const finalInput = assoc('fromType', 'Workspace', input);
  return createRelation(user, workspaceId, finalInput, { noLog: true }).then((relationData) => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const workspaceAddRelations = async (user, workspaceId, input) => {
  if (!input.through) {
    throw new ForbiddenAccess();
  }
  const finalInputs = map(
    (n) => ({
      fromType: 'Workspace',
      fromRole: input.fromRole,
      toId: n,
      toRole: input.toRole,
      through: input.through,
    }),
    input.toIds
  );
  await createRelations(user, workspaceId, finalInputs);
  return loadEntityById(workspaceId, 'Workspace').then((workspace) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};
export const workspaceEditField = (user, workspaceId, input) => {
  return executeWrite((wTx) => {
    return updateAttribute(user, workspaceId, 'Workspace', input, wTx, { noLog: true });
  }).then(async () => {
    const workspace = await loadEntityById(workspaceId, 'Workspace');
    return notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user);
  });
};
export const workspaceDeleteRelation = async (user, workspaceId, relationId) => {
  await deleteRelationById(user, relationId, 'stix_relation');
  const data = await loadEntityById(workspaceId, 'Workspace');
  return notify(BUS_TOPICS.Workspace.EDIT_TOPIC, data, user);
};
// endregion

// region context
export const workspaceCleanContext = (user, workspaceId) => {
  delEditContext(user, workspaceId);
  return loadEntityById(workspaceId, 'Workspace').then((workspace) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};
export const workspaceEditContext = (user, workspaceId, input) => {
  setEditContext(user, workspaceId, input);
  return loadEntityById(workspaceId, 'Workspace').then((workspace) =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};
// endregion
