import { expect, it, describe } from 'vitest';
import { v4 as uuid } from 'uuid';
import { getConnectorQueueDetails, metrics, purgeConnectorQueues, pushToConnector, registerConnectorQueues, unregisterConnector } from '../../../src/database/rabbitmq';
import { CONNECTOR_INTERNAL_IMPORT_FILE } from '../../../src/schema/general';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { RABBIT_QUEUE_PREFIX, waitInSec } from '../../../src/database/utils';

const testConnectorId = uuid();
describe('Rabbit connector management', () => {
  const connectorName = 'MY STIX IMPORTER';
  const connectorType = CONNECTOR_INTERNAL_IMPORT_FILE;
  const connectorScope = 'application/json';
  it('should register the connector', async () => {
    const config = await registerConnectorQueues(testConnectorId, connectorName, connectorType, connectorScope);
    expect(config.uri).not.toBeNull();
    expect(config.push).toEqual(`${RABBIT_QUEUE_PREFIX}push_${testConnectorId}`);
    expect(config.push_exchange).toEqual(`${RABBIT_QUEUE_PREFIX}amqp.worker.exchange`);
    expect(config.listen).toEqual(`${RABBIT_QUEUE_PREFIX}listen_${testConnectorId}`);
    expect(config.listen_exchange).toEqual(`${RABBIT_QUEUE_PREFIX}amqp.connector.exchange`);
  });
  it('should connector queues available', async () => {
    const data = await metrics(testContext, ADMIN_USER);
    expect(data.queues.length).toEqual(8);
    const aggregationMap = new Map(data.queues.map((q) => [q.name, q]));
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}listen_${testConnectorId}`)).toBeDefined();
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}push_${testConnectorId}`)).toBeDefined();
  });
  it('should queue size be avalaible', async () => {
    const queueDetail = await getConnectorQueueDetails(testConnectorId);
    expect(queueDetail.messages_number).toBe(0);
    expect(queueDetail.messages_size).toBe(0);
  });
  it('should push message to connector', async () => {
    await pushToConnector(testConnectorId, { id: uuid() });
  });
  it('should purge queue', async () => {
    const connectorData = { id: testConnectorId };
    await purgeConnectorQueues(connectorData);
    await waitInSec(2);
  });
  it('should delete connector', async () => {
    const unregister = await unregisterConnector(testConnectorId);
    expect(unregister.listen).not.toBeNull();
    expect(unregister.listen.messageCount).toEqual(0);
    expect(unregister.push).not.toBeNull();
    expect(unregister.push.messageCount).toEqual(0);
    const data = await metrics(testContext, ADMIN_USER);
    const aggregationMap = new Map(data.queues.map((q) => [q.name, q]));
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}listen_${testConnectorId}`)).toBeUndefined();
    expect(aggregationMap.get(`${RABBIT_QUEUE_PREFIX}push_${testConnectorId}`)).toBeUndefined();
  });
});
