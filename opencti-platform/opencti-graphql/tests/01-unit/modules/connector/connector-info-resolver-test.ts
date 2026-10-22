import { beforeEach, describe, expect, it, vi } from 'vitest';
import connectorResolvers from '../../../../src/modules/connector/connector-resolver';
import { redisGetConnectorErrors } from '../../../../src/modules/connector/connector-redis';

vi.mock('../../../../src/modules/connector/connector-redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-redis')>()),
  redisGetConnectorErrors: vi.fn(),
}));

type FieldResolver = (parent: unknown) => unknown;
const connectorInfoResolver = (connectorResolvers.Connector as Record<string, FieldResolver>).connector_info;
const errorsResolver = (connectorResolvers.ConnectorInfo as Record<string, FieldResolver>).errors;

const connectorInfo = { run_and_terminate: false, buffering: false, queue_threshold: 500, queue_messages_size: 0 };

describe('ConnectorInfo errors resolution', () => {
  beforeEach(() => {
    vi.mocked(redisGetConnectorErrors).mockReset();
  });

  it('should pass the connector id to connector_info without reading the errors', () => {
    expect(connectorInfoResolver({ internal_id: 'connector-1', connector_info: connectorInfo })).toEqual({ ...connectorInfo, connector_id: 'connector-1' });
    expect(redisGetConnectorErrors).not.toHaveBeenCalled();
  });

  it('should resolve no connector_info for a connector that never sent it', () => {
    expect(connectorInfoResolver({ internal_id: 'connector-1' })).toBeNull();
  });

  it('should read the errors of the connector only when they are requested', async () => {
    vi.mocked(redisGetConnectorErrors).mockResolvedValue([{ code: 'API_UNREACHABLE', message: '503', criticity: 2, last_seen_at: Date.now() }]);

    expect(await errorsResolver({ ...connectorInfo, connector_id: 'connector-1' })).toEqual([{ code: 'API_UNREACHABLE', message: '503', criticity: 2 }]);
    expect(redisGetConnectorErrors).toHaveBeenCalledWith('connector-1');
  });
});
