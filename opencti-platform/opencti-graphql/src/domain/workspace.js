import uuid from 'uuid/v4';
import { map } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import {
  createRelation,
  dayFormat,
  deleteEntityById,
  deleteRelationById,
  escapeString,
  executeWrite,
  getSingleValueNumber,
  graknNow,
  loadEntityById,
  loadWithConnectedRelations,
  monthFormat,
  paginate,
  prepareDate,
  updateAttribute,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elLoadById } from '../database/elasticSearch';
import { addMarkingDefs, addOwner } from './stixEntity';

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
  const internalId = workspace.internal_id_key ? escapeString(workspace.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const workspaceIterator = await wTx.tx.query(`insert $workspace isa Workspace,
      has internal_id_key "${internalId}",
      has entity_type "workspace",
      has workspace_type "${escapeString(workspace.workspace_type)}",
      has name "${escapeString(workspace.name)}",
      has description "${escapeString(workspace.description)}",
      has created_at ${graknNow()},
      has created_at_day "${dayFormat(graknNow())}",
      has created_at_month "${monthFormat(graknNow())}",
      has created_at_year "${yearFormat(graknNow())}",          
      has updated_at ${graknNow()};
    `);
    const createdWorkspace = await workspaceIterator.next();
    return createdWorkspace.map().get('workspace').id;
    // await wTx.tx.query(`match $from id ${createdWorkspaceId};
    //      $to has internal_id_key "${user.id}";
    //      insert (to: $from, owner: $to)
    //      isa owned_by, has internal_id_key "${uuid()}";`);
    // return internalId;
  });
  const created = await loadEntityById(internalId);
  await addOwner(internalId, user.id);
  await addMarkingDefs(internalId, workspace.markingDefinitions);
  return notify(BUS_TOPICS.Workspace.ADDED_TOPIC, created, user);
};

// region mutations
export const workspaceDelete = workspaceId => deleteEntityById(workspaceId);
export const workspaceAddRelation = (user, workspaceId, input) => {
  return createRelation(workspaceId, input).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });
};
export const workspaceAddRelations = async (user, workspaceId, input) => {
  const finalInput = map(
    n => ({
      toId: n,
      fromRole: input.fromRole,
      toRole: input.toRole,
      through: input.through
    }),
    input.toIds
  );

  await executeWrite(async wTx => {
    const createRelationPromise = relationInput =>
      wTx.tx.query(`match $from has internal_id_key ${workspaceId}; 
         $to has internal_id_key ${relationInput.toId}; 
         insert $rel(${relationInput.fromRole}: $from, ${relationInput.toRole}: $to) 
         isa ${relationInput.through}, has internal_id_key "${uuid()}";`);
    const relationsPromises = map(createRelationPromise, finalInput);
    await Promise.all(relationsPromises);
  });

  return loadEntityById(workspaceId).then(workspace => notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user));
};
export const workspaceEditField = (user, workspaceId, input) => {
  return executeWrite(wTx => {
    return updateAttribute(workspaceId, input, wTx);
  }).then(async () => {
    const workspace = await elLoadById(workspaceId);
    return notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user);
  });
};
export const workspaceDeleteRelation = (user, workspaceId, relationId) => {
  return deleteRelationById(workspaceId, relationId).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData.node, user);
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
