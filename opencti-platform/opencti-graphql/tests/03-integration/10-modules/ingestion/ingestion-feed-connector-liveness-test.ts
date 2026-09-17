import { afterAll, describe, expect, it } from 'vitest';
import { addIngestionCsv, deleteIngestionCsv, ingestionCsvEditField } from '../../../../src/modules/ingestion/ingestion-csv-domain';
import { connectorIdFromIngestId } from '../../../../src/domain/connector';
import { connector } from '../../../../src/database/repository';
import { redisGetConnectorHeartbeat } from '../../../../src/modules/connector/connector-redis';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { IngestionAuthType } from '../../../../src/generated/graphql';

// ---------------------------------------------------------------------------
// OpenCTI-Platform/opencti#18851: built-in feeds are registered as built-in
// connectors (feed twins), which never ping. Their liveness is the running state
// of the feed, they have no heartbeat and no last seen date.
// ---------------------------------------------------------------------------

describe('Built-in feed connector liveness', () => {
  let feedId: string;

  afterAll(async () => {
    if (feedId) {
      await deleteIngestionCsv(testContext, ADMIN_USER, feedId);
    }
  });

  const loadFeedConnector = async () => {
    const twinConnectorId = connectorIdFromIngestId(feedId);
    const feedConnector = await connector(testContext, ADMIN_USER, twinConnectorId);
    return { feedConnector, heartbeat: await redisGetConnectorHeartbeat(twinConnectorId) };
  };

  it('should follow the running state of the feed, without heartbeat nor last seen date', async () => {
    const feed = await addIngestionCsv(testContext, ADMIN_USER, {
      authentication_type: IngestionAuthType.None,
      name: 'CSV feed connector liveness',
      uri: 'http://fakefeed.invalid',
      user_id: ADMIN_USER.id,
    });
    feedId = feed.id;

    const created = await loadFeedConnector();
    expect(created.feedConnector.built_in).toBe(true);
    expect(created.feedConnector.active).toBe(false);
    expect(created.feedConnector.last_seen_at).toBeNull();
    expect(created.heartbeat).toBeNull();

    // Starting and stopping the feed registers its connector again
    await ingestionCsvEditField(testContext, ADMIN_USER, feedId, [{ key: 'ingestion_running', value: [true] }]);
    const started = await loadFeedConnector();
    expect(started.feedConnector.active).toBe(true);
    expect(started.feedConnector.last_seen_at).toBeNull();
    expect(started.heartbeat).toBeNull();

    await ingestionCsvEditField(testContext, ADMIN_USER, feedId, [{ key: 'ingestion_running', value: [false] }]);
    const stopped = await loadFeedConnector();
    expect(stopped.feedConnector.active).toBe(false);
    expect(stopped.heartbeat).toBeNull();
  });
});
