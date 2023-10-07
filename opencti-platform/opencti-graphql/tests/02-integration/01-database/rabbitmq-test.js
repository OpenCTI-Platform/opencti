import { expect, it, describe } from 'vitest';
import { v4 as uuid } from 'uuid';
import {
  metrics,
  pushToConnector,
  registerConnectorQueues,
  unregisterConnector,
} from '../../../src/database/rabbitmq';
import { CONNECTOR_INTERNAL_IMPORT_FILE } from '../../../src/schema/general';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { RABBIT_QUEUE_PREFIX } from '../../../src/database/utils';

describe('Rabbit basic and utils', () => {
  it('should rabbit metrics accurate', async () => {
    // Just wait one second to let redis client initialize
    const data = await metrics(testContext, ADMIN_USER);
    expect(data).not.toBeNull();
  });
});

describe('Rabbit connector management', () => {
  const connectorId = uuid();
  const connectorName = 'MY STIX IMPORTER';
  const connectorType = CONNECTOR_INTERNAL_IMPORT_FILE;
  const connectorScope = 'application/json';
  it('should register the connector', async () => {
    const config = await registerConnectorQueues(connectorId, connectorName, connectorType, connectorScope);
    expect(config.uri).not.toBeNull();
    expect(config.push).toEqual(`${RABBIT_QUEUE_PREFIX}push_${connectorId}`);
    expect(config.push_exchange).toEqual(`${RABBIT_QUEUE_PREFIX}amqp.worker.exchange`);
    expect(config.listen).toEqual(`${RABBIT_QUEUE_PREFIX}listen_${connectorId}`);
    expect(config.listen_exchange).toEqual(`${RABBIT_QUEUE_PREFIX}amqp.connector.exchange`);
  });
  it('should connector queues available', async () => {
    const data = await metrics(testContext, ADMIN_USER);
    expect(data).not.toBeNull();
    expect(data.queues.length).toEqual(6);
    const aggregationMap = new Map(data.queues.map((q) => [q.name, q]));
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}listen_${connectorId}`)).not.toBeUndefined();
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}push_${connectorId}`)).not.toBeUndefined();
  });
  it('should push message to connector', async () => {
    const connector = { internal_id: connectorId };
    await pushToConnector(testContext, connector, { id: uuid() });
  });
  it('should delete connector', async () => {
    const unregister = await unregisterConnector(connectorId);
    expect(unregister.listen).not.toBeNull();
    expect(unregister.listen.messageCount).toEqual(1);
    expect(unregister.push).not.toBeNull();
    expect(unregister.push.messageCount).toEqual(0);
    const data = await metrics(testContext, ADMIN_USER);
    const aggregationMap = new Map(data.queues.map((q) => [q.name, q]));
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}listen_${connectorId}`)).toBeUndefined();
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}push_${connectorId}`)).toBeUndefined();
  });
});
