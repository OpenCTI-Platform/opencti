import { logApp } from '../config/conf';
import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { SETTINGS_SET_ACCESSES } from '../utils/access';

const message = '[MIGRATION] Add scope in query and list background tasks';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  // 01. update QUERY tasks
  // 1.1 user query tasks = query tasks with a filter on entity_type=Notification
  const updateQueryForUserQueryTasks = {
    script: {
      params: {
        scope: 'USER',
        authorized_authorities: [SETTINGS_SET_ACCESSES],
      },
      source: 'ctx._source.scope = params.scope;'
        + ' ctx._source.authorized_authorities = params.authorized_authorities;'
        + ' ctx._source.authorized_members = [["id":ctx._source.initiator_id, "access_right": "admin"]];'
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'BackgroundTask' } } },
          { term: { 'type.keyword': { value: 'QUERY' } } },
          { match: { task_filters: '*Notification*' } },
        ],
      },
    },
  };
  const query1 = elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQueryForUserQueryTasks
  }).catch((err) => {
    throw DatabaseError('Error updating elastic for user query tasks', { error: err });
  });
  // 1.2. knowledge query tasks
  const updateQueryForKnowledgeQueryTasks = {
    script: {
      params: {
        scope: 'KNOWLEDGE',
        authorized_authorities: ['KNOWLEDGE_KNUPDATE'],
      },
      source: 'ctx._source.scope = params.scope;'
        + ' ctx._source.authorized_authorities = params.authorized_authorities;'
        + ' ctx._source.authorized_members = [["id":ctx._source.initiator_id, "access_right": "admin"]];'
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'BackgroundTask' } } },
          { term: { 'type.keyword': { value: 'QUERY' } } },
        ],
        must_not: [
          { match: { task_filters: '*Notification*' } },
        ]
      },
    },
  };
  const query2 = elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQueryForKnowledgeQueryTasks
  }).catch((err) => {
    throw DatabaseError('Error updating elastic for knowledge query tasks', { error: err });
  });

  // 02. update LIST tasks
  // 2.1 user list tasks = list tasks that modify the value of the is_read attribute of notifications
  // (deletion of notifications are considered knowledge tasks for technical concerns)
  const updateQueryForUserListTasks = {
    script: {
      params: {
        scope: 'USER',
        authorized_authorities: [SETTINGS_SET_ACCESSES],
      },
      source: 'ctx._source.scope = params.scope;'
        + ' ctx._source.authorized_authorities = params.authorized_authorities;'
        + ' ctx._source.authorized_members = [["id":ctx._source.initiator_id, "access_right": "admin"]];'
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'BackgroundTask' } } },
          { term: { 'type.keyword': { value: 'LIST' } } },
          { term: { 'actions.context.field.keyword': { value: 'is_read' } } },
        ],
      },
    },
  };
  const query3 = elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQueryForUserListTasks
  }).catch((err) => {
    throw DatabaseError('Error updating elastic for user list tasks', { error: err });
  });
  // 2.2 knowledge list tasks
  const updateQueryForKnowledgeListTasks = {
    script: {
      params: {
        scope: 'KNOWLEDGE',
        authorized_authorities: ['KNOWLEDGE_KNUPDATE'],
      },
      source: 'ctx._source.scope = params.scope;'
        + ' ctx._source.authorized_authorities = params.authorized_authorities;'
        + ' ctx._source.authorized_members = ctx._source.authorized_members = [["id":ctx._source.initiator_id, "access_right": "admin"]];'
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'BackgroundTask' } } },
          { term: { 'type.keyword': { value: 'LIST' } } },
        ],
        must_not: [
          { term: { 'actions.context.field.keyword': { value: 'is_read' } } },
        ]
      },
    },
  };
  const query4 = elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQueryForKnowledgeListTasks
  }).catch((err) => {
    throw DatabaseError('Error updating elastic for knowledge list tasks', { error: err });
  });

  await Promise.all([query1, query2, query3, query4]);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
