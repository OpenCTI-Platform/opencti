import { map } from 'ramda';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID, monthFormat,
  notify,
  now,
  paginate,
  paginateRelationships,
  qkObjUnique,
  takeTx, yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Workspace', args);

export const findById = workspaceId => loadByID(workspaceId);

export const ownedBy = workspaceId =>
  qkObjUnique(
    `match $x isa User; 
    $rel(owner:$x, to:$workspace) isa owned_by; 
    $workspace id ${workspaceId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const markingDefinitions = (workspaceId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$workspace) isa object_marking_refs; 
    $workspace id ${workspaceId}`,
    args
  );

export const objectRefs = (workspaceId, args) =>
  paginate(
    `match $so isa Stix-Domain-Entity; 
    $rel(so:$so, knowledge_aggregation:$workspace) isa object_refs; 
    $workspace id ${workspaceId}`,
    args
  );

export const relationRefs = (workspaceId, args) =>
  paginateRelationships(
    `match $rel($from, $to) isa stix_relation; 
    $extraRel(so:$rel, knowledge_aggregation:$workspace) isa object_refs; 
    $workspace id ${workspaceId}`,
    args,
    'extraRel'
  );

export const addWorkspace = async (user, workspace) => {
  const wTx = await takeTx();
  const workspaceIterator = await wTx.query(`insert $workspace isa Workspace 
    has type "workspace";
    $workspace has name "${workspace.name}";
    $workspace has description "${workspace.description}";
    $workspace has name_lowercase "${workspace.name.toLowerCase()}";
    $workspace has description_lowercase "${
      workspace.description ? workspace.description.toLowerCase() : ''
    }";
    $workspace has created_at ${now()};
    $workspace has created_at_month "${monthFormat(now())}";
    $workspace has created_at_year "${yearFormat(now())}";          
    $workspace has updated_at ${now()};
  `);
  const createdWorkspace = await workspaceIterator.next();
  const createdWorkspaceId = await createdWorkspace.map().get('workspace').id;

  await wTx.query(`match $from id ${createdWorkspaceId};
         $to id ${user.id};
         insert (to: $from, owner: $to)
         isa owned_by;`);

  if (workspace.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdWorkspaceId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      workspace.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  await wTx.commit();

  return loadByID(createdWorkspaceId).then(created =>
    notify(BUS_TOPICS.Workspace.ADDED_TOPIC, created, user)
  );
};

export const workspaceDelete = workspaceId => deleteByID(workspaceId);

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

  const wTx = await takeTx();
  const createRelationPromise = relationInput =>
    wTx.query(`match $from id ${workspaceId}; 
         $to id ${relationInput.toId}; 
         insert $rel(${relationInput.fromRole}: $from, ${
      relationInput.toRole
    }: $to) 
         isa ${relationInput.through};`);

  const relationsPromises = map(createRelationPromise, finalInput);
  await Promise.all(relationsPromises);

  await wTx.commit();

  return loadByID(workspaceId).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};

export const workspaceDeleteRelation = (user, workspaceId, relationId) =>
  deleteRelation(workspaceId, relationId).then(relationData => {
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const workspaceCleanContext = (user, workspaceId) => {
  delEditContext(user, workspaceId);
  return loadByID(workspaceId).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};

export const workspaceEditContext = (user, workspaceId, input) => {
  setEditContext(user, workspaceId, input);
  return loadByID(workspaceId).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
};

export const workspaceEditField = (user, workspaceId, input) =>
  editInputTx(workspaceId, input).then(workspace =>
    notify(BUS_TOPICS.Workspace.EDIT_TOPIC, workspace, user)
  );
