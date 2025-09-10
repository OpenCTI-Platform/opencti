import { logMigration } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_PLATFORM_INDICES } from '../database/utils';

const message = '[MIGRATION] remove obsolete fields not part of mapping';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const fieldsToRemove = ['authorized_members', // has been renamed to restricted_members
    'spec_version', 'representative', 'objectOrganization', 'marking_definitions', 'groups', 'caseTemplates', 'nodes_status',
    'fromType', 'toType', 'rel_has-reference', 'rel_has-reference.internal_id', 'rel_can-share', 'rel_can-share.internal_id',
    'i_valid_from_day', 'i_valid_until_day', 'i_valid_from_month', 'i_valid_until_month', 'i_valid_from_year', 'i_valid_until_year',
    'i_stop_time_year', 'i_start_time_year', 'i_start_time_month', 'i_stop_time_month', 'i_start_time_day', 'i_stop_time_day',
    'i_created_at_year', 'i_created_at_month', 'i_created_at_day',
  ];
  const updateQuery = {
    script: {
      params: { fieldsToRemove },
      source: 'for(def field : params.fieldsToRemove) ctx._source.remove(field)'
    },
    query: {
      match_all: {},
    },
  };
  await elUpdateByQueryForMigration(
    message,
    READ_PLATFORM_INDICES,
    updateQuery
  );
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
