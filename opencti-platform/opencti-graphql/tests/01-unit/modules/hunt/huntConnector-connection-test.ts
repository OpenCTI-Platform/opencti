import { beforeEach, describe, expect, it, vi } from 'vitest';
import { pushToConnector } from '../../../../src/database/rabbitmq';
import { deleteWork } from '../../../../src/domain/work';
import { withHuntLock } from '../../../../src/modules/hunt/hunt-lock';
import { reportHuntConnectorCheck, testHuntConnectorConnection } from '../../../../src/modules/hunt/huntRun/huntRun-domain';
import type { AuthUser } from '../../../../src/types/user';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

// The stored connector: every read returns what the last write left
const store = vi.hoisted(() => ({ connector: {} as Record<string, unknown> }));

vi.mock('../../../../src/modules/hunt/hunt-dispatch', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/hunt/hunt-dispatch')>(),
  listHuntConnectors: vi.fn(async () => [{ ...store.connector }]),
}));

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware')>(),
  patchAttribute: vi.fn(async (_context, _user, _id, _type, patch) => {
    Object.assign(store.connector, patch);
    return { element: { ...store.connector } };
  }),
}));

// A platform-wide lock: the actions of a key run one after the other
vi.mock('../../../../src/modules/hunt/hunt-lock', () => {
  const chains = new Map<string, Promise<unknown>>();
  return {
    withHuntLock: vi.fn(async (key: string, action: () => Promise<unknown>) => {
      const run = (chains.get(key) ?? Promise.resolve()).then(action);
      chains.set(key, run.catch(() => undefined));
      return run;
    }),
  };
});

vi.mock('../../../../src/domain/work', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/domain/work')>(),
  createWork: vi.fn(async () => ({ id: 'work-1' })),
  deleteWork: vi.fn(async () => undefined),
}));

vi.mock('../../../../src/database/rabbitmq', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/rabbitmq')>(),
  pushToConnector: vi.fn(),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  notify: vi.fn(async (_topic, instance) => instance),
}));

vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/listener/UserActionListener')>(),
  publishUserAction: vi.fn(),
}));

const PASSED = { id: 'check-0', status: 'passed', requested_at: '2026-10-06T08:00:00.000Z', checked_at: '2026-10-06T08:00:05.000Z', checks: [] };
const storedCheck = () => store.connector.hunt_connection_check as { id: string; status: string };
const wait = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

describe('Connection test of a hunt connector', () => {
  beforeEach(() => {
    store.connector = {
      internal_id: 'connector-1',
      name: 'Splunk hunt',
      active: true,
      connector_user_id: ADMIN_USER.id,
      hunt_platform: 'splunk',
      hunt_connection_check: PASSED,
    };
    vi.mocked(pushToConnector).mockReset();
    vi.mocked(deleteWork).mockClear();
  });

  it('should restore the previous result when the test cannot be sent', async () => {
    vi.mocked(pushToConnector).mockRejectedValueOnce(new Error('queue unavailable'));
    await expect(testHuntConnectorConnection(testContext, ADMIN_USER, 'connector-1')).rejects.toThrow('queue unavailable');
    expect(storedCheck()).toEqual(PASSED);
    expect(deleteWork).toHaveBeenCalledWith(testContext, expect.anything(), 'work-1');
  });

  it('should never let a test that cannot be sent overwrite a newer test', async () => {
    // The first test fails to publish only after a while, the second one is requested meanwhile
    vi.mocked(pushToConnector)
      .mockImplementationOnce(async () => {
        await wait(20);
        throw new Error('queue unavailable');
      })
      .mockResolvedValueOnce(undefined as never);
    const first = testHuntConnectorConnection(testContext, ADMIN_USER, 'connector-1');
    const second = testHuntConnectorConnection(testContext, ADMIN_USER, 'connector-1');
    await expect(first).rejects.toThrow('queue unavailable');
    const view = await second;
    expect(storedCheck().status).toEqual('pending');
    expect(storedCheck().id).toEqual(view.connection_check?.id);
    expect(storedCheck().id).not.toEqual(PASSED.id);
  });

  it('should take the answer of the connector after the test being sent, and refuse the answer to the test it replaced', async () => {
    vi.mocked(pushToConnector).mockImplementationOnce(async () => {
      await wait(20);
    });
    const requested = testHuntConnectorConnection(testContext, ADMIN_USER, 'connector-1');
    const late = reportHuntConnectorCheck(testContext, ADMIN_USER, { connector_id: 'connector-1', check_id: PASSED.id, checks: [{ name: 'Search', ok: true, message: 'Allowed' }] });
    await expect(late).rejects.toThrow('This connection test is not the last one requested for the connector');
    const view = await requested;
    const answered = await reportHuntConnectorCheck(testContext, ADMIN_USER, {
      connector_id: 'connector-1',
      check_id: view.connection_check?.id as string,
      work_id: 'work-1',
      checks: [{ name: 'Search', ok: false, message: 'The role cannot run searches' }],
    });
    expect(answered.connection_check?.status).toEqual('failed');
    expect(storedCheck().status).toEqual('failed');
  });

  it('should only take the answer given in the work the test was dispatched with', async () => {
    const view = await testHuntConnectorConnection(testContext, ADMIN_USER, 'connector-1');
    const answer = { connector_id: 'connector-1', check_id: view.connection_check?.id as string, checks: [{ name: 'Search', ok: true, message: 'Allowed' }] };
    await expect(reportHuntConnectorCheck(testContext, ADMIN_USER, { ...answer, work_id: 'work-2' })).rejects.toThrow('A hunt connector can only report the connection test it received');
    await expect(reportHuntConnectorCheck(testContext, ADMIN_USER, answer)).rejects.toThrow('A hunt connector can only report the connection test it received');
    expect(storedCheck().status).toEqual('pending');
    // The work of the message being processed, given by the call
    expect((await reportHuntConnectorCheck({ ...testContext, workId: 'work-1' }, ADMIN_USER, answer)).connection_check?.status).toEqual('passed');
  });

  it('should refuse the answer of the former user of a connector registered again with another user while the answer waited for the lock', async () => {
    const connectorUser = { ...ADMIN_USER, id: 'connector-user-1', capabilities: [{ name: 'CONNECTORAPI' }] } as AuthUser;
    const pending = { ...PASSED, id: 'check-1', work_id: 'work-1', status: 'pending', checked_at: null };
    store.connector.connector_user_id = connectorUser.id;
    store.connector.hunt_connection_check = pending;
    const answer = { connector_id: 'connector-1', check_id: pending.id, work_id: 'work-1', checks: [{ name: 'Search', ok: true, message: 'Allowed' }] };
    vi.mocked(withHuntLock).mockImplementationOnce(async (_key, action) => {
      store.connector.connector_user_id = 'connector-user-2';
      return action();
    });
    await expect(reportHuntConnectorCheck(testContext, connectorUser, answer)).rejects.toThrow('A hunt connector can only report its own connection test');
    expect(storedCheck().status).toEqual('pending');
    // The user of the connector answers its test
    store.connector.connector_user_id = connectorUser.id;
    expect((await reportHuntConnectorCheck(testContext, connectorUser, answer)).connection_check?.status).toEqual('passed');
  });
});
