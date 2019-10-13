import uuid from 'uuid/v4';
import { map } from 'ramda';
import { delEditContext, setEditContext } from '../database/redis';
import {
  escapeString,
  createRelation,
  deleteEntityById,
  deleteRelationById,
  getSingleValueNumber,
  updateAttribute,
  getById,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  graknNow,
  paginate,
  getObject,
  takeWriteTx,
  commitWriteTx,
  prepareDate
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

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

export const findById = workspaceId => getById(workspaceId);

export const workspacesNumber = args => {
  return {
    count: getSingleValueNumber(
      `match $x isa Workspace; ${
        args.endDate
          ? `$x has created_at $date; $date < ${prepareDate(args.endDate)};`
          : ''
      } get; count;`
    ),
    total: getSingleValueNumber(`match $x isa Workspace; get; count;`)
  };
};

export const ownedBy = workspaceId =>
  getObject(
    `match $x isa User; 
    $rel(owner:$x, to:$workspace) isa owned_by; 
    $workspace has internal_id "${escapeString(
      workspaceId
    )}"; get; offset 0; limit 1;`,
    'x',
    'rel'
  );

export const markingDefinitions = (workspaceId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$workspace) isa object_marking_refs; 
    $workspace has internal_id "${escapeString(workspaceId)}"`,
    args,
    false
  );

export const objectRefs = (workspaceId, args) =>
  paginate(
    `match $so isa Stix-Domain-Entity; 
    $rel(so:$so, knowledge_aggregation:$workspace) isa object_refs; 
    $workspace has internal_id "${escapeString(workspaceId)}"`,
    args,
    false
  );

export const addWorkspace = async (user, workspace) => {
  const wTx = await takeWriteTx();
  const internalId = workspace.internal_id
    ? escapeString(workspace.internal_id)
    : uuid();
  const workspaceIterator = await wTx.tx.query(`insert $workspace isa Workspace,
    has internal_id "${internalId}",
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
  const createdWorkspaceId = await createdWorkspace.map().get('workspace').id;

  await wTx.tx.query(`match $from id ${createdWorkspaceId};
         $to has internal_id "${user.id}";
         insert (to: $from, owner: $to)
         isa owned_by, has internal_id "${uuid()}";`);

  if (workspace.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdWorkspaceId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      workspace.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created =>
    notify(BUS_TOPICS.Workspace.ADDED_TOPIC, created, user)
  );
};

export const workspaceDelete = workspaceId => deleteEntityById(workspaceId);

export const workspaceAddRelation = (user, workspaceId, input) =>
  createRelation(workspaceId, input).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

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

  const wTx = await takeWriteTx();
  const createRelationPromise = relationInput =>
    wTx.tx.query(`match $from has internal_id ${workspaceId}; 
         $to has internal_id ${relationInput.toId}; 
         insert $rel(${relationInput.fromRole}: $from, ${
      relationInput.toRole
    }: $to) 
         isa ${relationInput.through}, has internal_id "${uuid()}";`);

  const relationsPromises = map(createRelationPromise, finalInput);
  await Promise.all(relationsPromises);

  await commitWriteTx(wTx);

  return getById(workspaceId).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};

export const workspaceDeleteRelation = (user, workspaceId, relationId) =>
  deleteRelationById(workspaceId, relationId).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const workspaceCleanContext = (user, workspaceId) => {
  delEditContext(user, workspaceId);
  return getById(workspaceId).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};

export const workspaceEditContext = (user, workspaceId, input) => {
  setEditContext(user, workspaceId, input);
  return getById(workspaceId).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};

export const workspaceEditField = (user, workspaceId, input) =>
  updateAttribute(workspaceId, input).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
