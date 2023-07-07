import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] Adding instance_trigger attribute to triggers';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  // triggers now have a mandatory boolean attribute 'instance_trigger'
  const updateQuery = {
    script: {
      params: { no_instance_trigger: false },
      source: 'ctx._source.instance_trigger = params.no_instance_trigger',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'trigger' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration(message, READ_DATA_INDICES, updateQuery)
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });

  // event_types of a trigger should contain at least 1 event
  const source = `if (ctx._source.trigger_type == params.live && ctx._source.event_types.length == params.zero) {
    ctx._source.event_types = params.createEvent;
  }`;
  const eventTypeUpdateQuery = {
    script: {
      params: { createEvent: ['create'], live: 'live', zero: 0 },
      source,
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'trigger' } } },
        ],
      },
    },
  };
  await elUpdateByQueryForMigration('[MIGRATION] Trigger event_types attribute modification', READ_DATA_INDICES, eventTypeUpdateQuery)
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });
  logApp.info('[MIGRATION] Trigger type modifications done.');
  next();
};

export const down = async (next) => {
  next();
};
