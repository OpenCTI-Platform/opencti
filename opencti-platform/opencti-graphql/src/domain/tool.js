import { assoc, head, join, map, tail } from 'ramda';
import uuid from 'uuid/v4';
import {
  dayFormat,
  escapeString,
  executeWrite,
  graknNow,
  loadEntityById,
  monthFormat,
  prepareDate,
  yearFormat
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { elLoadById, elPaginate } from '../database/elasticSearch';
import { addCreatedByRef, addKillChains, addMarkingDefs } from './stixEntity';
import { notify } from '../database/redis';

export const findById = toolId => elLoadById(toolId);
export const findAll = args => {
  return elPaginate('stix_domain_entities', assoc('type', 'tool', args));
};

export const addTool = async (user, tool) => {
  const internalId = tool.internal_id_key ? escapeString(tool.internal_id_key) : uuid();
  await executeWrite(async wTx => {
    const toolIterator = await wTx.tx.query(`insert $tool isa Tool,
    has internal_id_key "${internalId}",
    has entity_type "tool",
    has stix_id_key "${tool.stix_id_key ? escapeString(tool.stix_id_key) : `tool--${uuid()}`}",
    has stix_label "",
    ${
      tool.alias
        ? `${join(' ', map(val => `has alias "${escapeString(val)}",`, tail(tool.alias)))} has alias "${escapeString(
            head(tool.alias)
          )}",`
        : 'has alias "",'
    }
    has name "${escapeString(tool.name)}",
    has description "${escapeString(tool.description)}",
    has created ${tool.created ? prepareDate(tool.created) : graknNow()},
    has modified ${tool.modified ? prepareDate(tool.modified) : graknNow()},
    has revoked false,
    has created_at ${graknNow()},
    has created_at_day "${dayFormat(graknNow())}",
    has created_at_month "${monthFormat(graknNow())}",
    has created_at_year "${yearFormat(graknNow())}",      
    has updated_at ${graknNow()};
  `);
    const createTool = await toolIterator.next();
    return createTool.map().get('tool').id;
  });
  const created = await loadEntityById(internalId);
  await addCreatedByRef(internalId, tool.createdByRef);
  await addMarkingDefs(internalId, tool.markingDefinitions);
  await addKillChains(internalId, tool.killChainPhases);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};
