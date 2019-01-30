import { map } from 'ramda';
import uuid from 'uuid/v4';
import {
  deleteByID,
  loadByID,
  monthFormat,
  notify,
  now,
  paginate,
  takeTx,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';

export const findAll = args => paginate('match $m isa Tool', args);

export const findById = toolId => loadByID(toolId);

export const addTool = async (user, tool) => {
  const wTx = await takeTx();
  const toolIterator = await wTx.query(`insert $tool isa Tool 
    has type "tool";
    $tool has stix_id "tool--${uuid()}";
    $tool has stix_label "";
    $tool has stix_label_lowercase "";
    $tool has alias "";
    $tool has alias_lowercase "";
    $tool has name "${tool.name}";
    $tool has description "${tool.description}";
    $tool has name_lowercase "${tool.name.toLowerCase()}";
    $tool has description_lowercase "${
      tool.description ? tool.description.toLowerCase() : ''
    }";
    $tool has created ${now()};
    $tool has modified ${now()};
    $tool has revoked false;
    $tool has created_at ${now()};
    $tool has created_at_month "${monthFormat(now())}";
    $tool has created_at_year "${yearFormat(now())}";      
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
    notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user)
  );
};

export const toolDelete = toolId => deleteByID(toolId);
