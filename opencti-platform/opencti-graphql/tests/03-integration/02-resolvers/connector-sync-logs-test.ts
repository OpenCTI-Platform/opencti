import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { createEntity, deleteElementById } from '../../../src/database/middleware';
import {
  getClientBase,
  redisDeleteIngestionLogHistory,
  redisPushIngestionLog,
} from '../../../src/database/redis';
import { ENTITY_TYPE_SYNC } from '../../../src/schema/internalObject';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';

const READ_SYNC_LOGS_QUERY = gql`
  query readSynchronizerLogs($id: String!) {
    synchronizerLogs(id: $id) {
      level
      message
      type
      identifier
      meta
    }
  }
`;

const READ_SYNC_LOGS_FIELD_QUERY = gql`
  query readSynchronizerLogsField($id: String!) {
    synchronizer(id: $id) {
      id
      ingestionLogs {
        level
        message
      }
    }
  }
`;

describe('Connector resolver - stream logs', () => {
  let synchronizerId: string;
  const synchronizerName = 'sync-logs-test';

  beforeAll(async () => {
    const creationResult = await createEntity(testContext, ADMIN_USER, {
      name: synchronizerName,
      uri: 'http://localhost:4242',
      token: 'token',
      stream_id: 'stream--sync-logs-test',
      running: false,
      listen_deletion: true,
      no_dependencies: false,
      ssl_verify: false,
      synchronized: false,
      user_id: ADMIN_USER.id,
    }, ENTITY_TYPE_SYNC, { complete: true });
    const synchronizer = 'element' in creationResult ? creationResult.element : creationResult;
    synchronizerId = synchronizer.id;
    expect(synchronizerId).toBeDefined();
  });

  afterAll(async () => {
    if (synchronizerId) {
      await redisDeleteIngestionLogHistory(synchronizerId);
      await deleteElementById(testContext, ADMIN_USER, synchronizerId, ENTITY_TYPE_SYNC);
    }
  });

  it('should resolve logs from synchronizerLogs query and ingestionLogs field', async () => {
    await redisDeleteIngestionLogHistory(synchronizerId);
    await redisPushIngestionLog(synchronizerId, {
      level: 'info',
      type: 'sync',
      identifier: synchronizerName,
      message: 'info-log',
      meta: { step: 1 },
    });
    await redisPushIngestionLog(synchronizerId, {
      level: 'success',
      type: 'sync',
      identifier: synchronizerName,
      message: 'success-log',
      meta: { step: 2 },
    });
    await redisPushIngestionLog(synchronizerId, {
      level: 'warn',
      type: 'sync',
      identifier: synchronizerName,
      message: 'warn-log',
      meta: { step: 3 },
    });
    await redisPushIngestionLog(synchronizerId, {
      level: 'error',
      type: 'sync',
      identifier: synchronizerName,
      message: 'error-log',
      meta: { step: 4 },
    });

    const queryLogsResult = await queryAsAdminWithSuccess({
      query: READ_SYNC_LOGS_QUERY,
      variables: { id: synchronizerId },
    });
    expect(queryLogsResult.data?.synchronizerLogs).toHaveLength(4);
    expect(queryLogsResult.data?.synchronizerLogs.map((l: { level: string }) => l.level)).toEqual(['error', 'warn', 'success', 'info']);
    expect(queryLogsResult.data?.synchronizerLogs[0].message).toBe('error-log');

    const fieldLogsResult = await queryAsAdminWithSuccess({
      query: READ_SYNC_LOGS_FIELD_QUERY,
      variables: { id: synchronizerId },
    });
    expect(fieldLogsResult.data?.synchronizer.ingestionLogs).toHaveLength(4);
    expect(fieldLogsResult.data?.synchronizer.ingestionLogs.map((l: { level: string }) => l.level)).toEqual(['error', 'warn', 'success', 'info']);
  });

  it('should fail when encountering an unknown log level', async () => {
    await redisDeleteIngestionLogHistory(synchronizerId);
    await getClientBase().lpush(`ingestion-log-${synchronizerId}-history`, JSON.stringify({
      timestamp: new Date().toISOString(),
      level: 'unknown_level',
      type: 'sync',
      identifier: synchronizerName,
      message: 'bad-level',
      meta: {},
    }));

    const result = await queryAsAdmin({
      query: READ_SYNC_LOGS_QUERY,
      variables: { id: synchronizerId },
    });
    expect(result.errors).toBeDefined();
    if (result.errors) {
      expect(result.errors[0].message).toContain('Unknown ingestion log level');
    }
  });
});
