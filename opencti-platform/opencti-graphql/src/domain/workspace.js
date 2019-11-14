import { assoc, map } from 'ramda';
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
  loadEntityById,
  loadWithConnectedRelations,
  paginate,
  prepareDate,
  TYPE_OPENCTI_INTERNAL,
  updateAttribute
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

// region grakn fetch
export const findById = workspaceId => {
  return loadEntityById(workspaceId);
};
export const findAll = args => {
  return paginate(
    `match $w isa Workspace${
      args.workspaceType
        ? `; 
    $w has workspace_type "${escapeString(args.workspaceType)}"`
        : ''
    }${
      args.search
        ? `; $w has name $name;
   $w has description $description;
   { $name contains "${escapeString(args.search)}"; } or
   { $description contains "${escapeString(args.search)}"; }`
        : ''
    }`,
    args
  );
};
export const workspacesNumber = args => {
  return {
    count: getSingleValueNumber(
      `match $x isa Workspace; ${
        args.endDate ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};` : ''
      } get; count;`
    ),
    total: getSingleValueNumber(`match $x isa Workspace; get; count;`)
  };
};
export const ownedBy = workspaceId => {
  return loadWithConnectedRelations(
    `match $x isa User; 
    $rel(owner:$x, to:$workspace) isa owned_by; 
    $workspace has internal_id_key "${escapeString(workspaceId)}"; get; offset 0; limit 1;`,
    'x',
    'rel'
  );
};
export const objectRefs = (workspaceId, args) => {
  return paginate(
    `match $so isa Stix-Domain-Entity; 
    $rel(so:$so, knowledge_aggregation:$workspace) isa object_refs; 
    $workspace has internal_id_key "${escapeString(workspaceId)}"`,
    args,
    false
  );
};
// endregion

export const addWorkspace = async (user, workspace) => {
  const workspaceToCreate = assoc('createdByOwner', user.id, workspace);
  const created = await createEntity(workspaceToCreate, 'Workspace', TYPE_OPENCTI_INTERNAL);
  return notify(BUS_TOPICS.Workspace.ADDED_TOPIC, created, user);
};

// region mutations
export const workspaceDelete = workspaceId => deleteEntityById(workspaceId);
export const workspaceAddRelation = (user, workspaceId, input) => {
  return createRelation(workspaceId, input).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
export const workspaceAddRelations = async (user, workspaceId, input) => {
  const finalInputs = map(
    n => ({
      toId: n,
      fromRole: input.fromRole,
      toRole: input.toRole,
      through: input.through
    }),
    input.toIds
  );
  await createRelations(workspaceId, finalInputs);
  return loadEntityById(workspaceId).then(workspace => notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user));
};
export const workspaceEditField = (user, workspaceId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(workspaceId, input, wTx);
  }).then(async () => {
    const workspace = await loadEntityById(workspaceId);
    return notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user);
  });
};
export const workspaceDeleteRelation = (user, workspaceId, relationId) => {
  return deleteRelationById(workspaceId, relationId).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData, user);
    return relationData;
  });
};
// endregion

// region context
export const workspaceCleanContext = (user, workspaceId) => {
  delEditContext(user, workspaceId);
  return loadEntityById(workspaceId).then(workspace => notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user));
};
export const workspaceEditContext = (user, workspaceId, input) => {
  setEditContext(user, workspaceId, input);
  return loadEntityById(workspaceId).then(workspace => notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user));
};
// endregion
