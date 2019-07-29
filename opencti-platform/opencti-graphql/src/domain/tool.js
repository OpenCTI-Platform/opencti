import { assoc, map } from 'ramda';
import uuid from 'uuid/v4';
import {
  escapeString,
  getById,
  prepareDate,
  dayFormat,
  monthFormat,
  yearFormat,
  notify,
  now,
  takeWriteTx,
  commitWriteTx
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { index, paginate as elPaginate } from '../database/elasticSearch';

export const findAll = args =>
  elPaginate('stix_domain_entities', assoc('type', 'tool', args));
// paginate('match $t isa Tool', args);

export const findById = toolId => getById(toolId);

export const addTool = async (user, tool) => {
  const wTx = await takeWriteTx();
  const internalId = tool.internal_id ? escapeString(tool.internal_id) : uuid();
  const toolIterator = await wTx.tx.query(`insert $tool isa Tool,
    has internal_id "${internalId}",
    has entity_type "tool",
    has stix_id "${
      tool.stix_id ? escapeString(tool.stix_id) : `tool--${uuid()}`
    }",
    has stix_label "",
    has alias "",
    has name "${escapeString(tool.name)}",
    has description "${escapeString(tool.description)}",
    has created ${tool.created ? prepareDate(tool.created) : now()},
    has modified ${tool.modified ? prepareDate(tool.modified) : now()},
    has revoked false,
    has created_at ${now()},
    has created_at_day "${dayFormat(now())}",
    has created_at_month "${monthFormat(now())}",
    has created_at_year "${yearFormat(now())}",      
    has updated_at ${now()};
  `);
  const createTool = await toolIterator.next();
  const createdToolId = await createTool.map().get('tool').id;

  if (tool.createdByRef) {
    await wTx.tx.query(
      `match $from id ${createdToolId};
      $to has internal_id "${escapeString(tool.createdByRef)}";
      insert (so: $from, creator: $to)
      isa created_by_ref, has internal_id "${uuid()}";`
    );
  }

  if (tool.markingDefinitions) {
    const createMarkingDefinition = markingDefinition =>
      wTx.tx.query(
        `match $from id ${createdToolId}; 
        $to has internal_id "${escapeString(markingDefinition)}"; 
        insert (so: $from, marking: $to) isa object_marking_refs, has internal_id "${uuid()}";`
      );
    const markingDefinitionsPromises = map(
      createMarkingDefinition,
      tool.markingDefinitions
    );
    await Promise.all(markingDefinitionsPromises);
  }

  if (tool.killChainPhases) {
    const createKillChainPhase = killChainPhase =>
      wTx.tx.query(
        `match $from id ${createdToolId}; 
        $to has internal_id "${escapeString(killChainPhase)}"; 
        insert (phase_belonging: $from, kill_chain_phase: $to) isa kill_chain_phases, has internal_id "${uuid()}";`
      );
    const killChainPhasesPromises = map(
      createKillChainPhase,
      tool.killChainPhases
    );
    await Promise.all(killChainPhasesPromises);
  }

  await commitWriteTx(wTx);

  return getById(internalId).then(created => {
    index('stix_domain_entities', created);
    return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
  });
};
