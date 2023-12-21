import { logApp } from '../config/conf';
import { elRawUpdateByQuery } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { DatabaseError } from '../config/errors';

const message = '[MIGRATION] Renaming platform messages attribute';

const renamePlatformMessages = async () => {
  const updateQuery = {
    script: {
      source: "ctx._source.platform_messages = ctx._source.messages; ctx._source.remove('messages')",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Settings' } } },
        ],
      },
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

const renameNotificationContent = async () => {
  const updateQuery = {
    script: {
      source: "ctx._source.notification_content = ctx._source.content; ctx._source.remove('content')",
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'Notification' } } },
        ],
      },
    },
  };
  await elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    wait_for_completion: true,
    body: updateQuery
  }).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });
};

export const up = async (next) => {
  logApp.info(`${message} > started`);
  await renamePlatformMessages();
  await renameNotificationContent();
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
