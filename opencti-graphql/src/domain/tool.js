import { map } from 'ramda';
import uuid from 'uuid/v4';
import { delEditContext, setEditContext } from '../database/redis';
import {
  createRelation,
  deleteByID,
  deleteRelation,
  editInputTx,
  loadByID,
  notify,
  now,
  paginate,
  qkObjUnique,
  takeTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Tool', args);

export const findById = toolId => loadByID(toolId);

export const createdByRef = toolId =>
  qkObjUnique(
    `match $x isa Identity; 
    $rel(creator:$x, so:$tool) isa created_by_ref; 
    $tool id ${toolId}; offset 0; limit 1; get $x,$rel;`,
    'x',
    'rel'
  );

export const markingDefinitions = (toolId, args) =>
  paginate(
    `match $marking isa Marking-Definition; 
    $rel(marking:$marking, so:$tool) isa object_marking_refs; 
    $tool id ${toolId}`,
    args
  );

export const killChainPhases = (toolId, args) =>
  paginate(
    `match $kc isa Kill-Chain-Phase; 
    $rel(kill_chain_phase:$kc, phase_belonging:$tool) isa kill_chain_phases; 
    $tool id ${toolId}`,
    args
  );

export const reports = (toolId, args) =>
  paginate(
    `match $report isa Report; 
    $rel(knowledge_aggregation:$report, so:$tool) isa object_refs; 
    $tool id ${toolId}`,
    args
  );

export const addTool = async (user, tool) => {
  const wTx = await takeTx();
  const toolIterator = await wTx.query(`insert $tool isa Tool 
    has type "tool";
    $tool has stix_id "tool--${uuid()}";
    $tool has name "${tool.name}";
    $tool has description "${tool.description}";
    $tool has created ${now()};
    $tool has modified ${now()};
    $tool has revoked false;
    $tool has created_at ${now()};
    $tool has updated_at ${now()};
  `);
  const createTool = await toolIterator.next();
  const createdToolId = await createTool.map().get('tool').id;

  if (tool.createdByRef) {
    await wTx.query(`match $from id ${createdToolId};
         $to id ${tool.createdByRef};
         insert (so: $from, creator: $to)
         isa created_by_ref;`);
  }

  if (tool.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.query(
        `match $from id ${createdToolId}; $to id ${markingDefinition}; insert (so: $from, marking: $to) isa object_marking_refs;`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      tool.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (tool.killChainPhases) {
    const createKillChainPhase = killChainPhase =>
      wTx.query(
        `match $from id ${createdToolId}; $to id ${killChainPhase}; insert (phase_belonging: $from, kill_chain_phase: $to) isa kill_chain_phases;`
      );
    const killChainPhasesPromises = map(
      createKillChainPhase,
      tool.killChainPhases
    );
    await Promise.all(killChainPhasesPromises);
  }

  await wTx.commit();

  return loadByID(createdToolId).then(created =>
    notify(BUS_TOPICS.Tool.ADDED_TOPIC, created, user)
  );
};

export const toolDelete = toolId => deleteByID(toolId);

export const toolAddRelation = (user, toolId, input) =>
  createRelation(toolId, input).then(relationData => {
    notify(BUS_TOPICS.Tool.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const toolDeleteRelation = (user, toolId, relationId) =>
  deleteRelation(toolId, relationId).then(relationData => {
    notify(BUS_TOPICS.Tool.EDIT_TOPIC, relationData.node, user);
    return relationData;
  });

export const toolCleanContext = (user, toolId) => {
  delEditContext(user, toolId);
  return loadByID(toolId).then(tool =>
    notify(BUS_TOPICS.Tool.EDIT_TOPIC, tool, user)
  );
};

export const toolEditContext = (user, toolId, input) => {
  setEditContext(user, toolId, input);
  return loadByID(toolId).then(tool =>
    notify(BUS_TOPICS.Tool.EDIT_TOPIC, tool, user)
  );
};

export const toolEditField = (user, toolId, input) =>
  editInputTx(toolId, input).then(tool =>
    notify(BUS_TOPICS.Tool.EDIT_TOPIC, tool, user)
  );
