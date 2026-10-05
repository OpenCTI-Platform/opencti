import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildRun } from './investigationRun-fixtures';

const mocks = vi.hoisted(() => ({
  events: [] as unknown[],
  run: null as unknown,
  access: true,
  closed: vi.fn(async () => ({ value: undefined, done: true })),
}));

vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>(),
  checkEnterpriseEdition: vi.fn(async () => undefined),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/middleware-loader')>(),
  internalLoadById: vi.fn(async () => ({ id: 'run-1' })),
}));
vi.mock('../../../../src/modules/investigationRun/investigationRun-domain', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/modules/investigationRun/investigationRun-domain')>(),
  loadInvestigationRun: vi.fn(async () => mocks.run),
}));
vi.mock('../../../../src/graphql/subscriptionWrapper', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/graphql/subscriptionWrapper')>(),
  canSubscriberStillAccess: vi.fn(async () => mocks.access),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  pubSubAsyncIterator: vi.fn(() => {
    const queue = [...mocks.events];
    return {
      next: async () => (queue.length > 0 ? { value: queue.shift(), done: false } : { value: undefined, done: true }),
      return: mocks.closed,
    };
  }),
}));

const { default: investigationRunResolvers } = await import('../../../../src/modules/investigationRun/investigationRun-resolvers');
const { pubSubAsyncIterator } = await import('../../../../src/database/redis');
const { BUS_TOPICS } = await import('../../../../src/config/conf');
const { ENTITY_TYPE_PIR } = await import('../../../../src/modules/pir/pir-types');

type Subscribe = (parent: unknown, args: { id: string }, context: unknown) => Promise<AsyncIterable<{ instance: { id: string } }>>;
const subscribe = (investigationRunResolvers.Subscription as unknown as { investigationRun: { subscribe: Subscribe } }).investigationRun.subscribe;
const listen = async () => (await subscribe(undefined, { id: 'run-1' }, { user: { id: 'user-1' } }))[Symbol.asyncIterator]();

describe('Case Autopilot run subscription', () => {
  beforeEach(() => {
    mocks.run = buildRun();
    mocks.access = true;
    mocks.closed.mockClear();
  });

  it('delivers the run on its own events and when one of its sources changes, never on unrelated objects', async () => {
    mocks.events = [
      { instance: { id: 'unrelated-entity' } },
      // A marking added to the investigated incident: the open view is served the run again.
      { instance: { id: 'incident-1' } },
      { instance: buildRun({ name: 'Renamed' }) },
    ];
    const iterator = await listen();
    expect((await iterator.next()).value).toEqual({ instance: mocks.run });
    expect((await iterator.next()).value?.instance).toMatchObject({ id: 'run-1', name: 'Renamed' });
    expect((await iterator.next()).done).toBe(true);
  });

  it('follows the edits of every kind of source a run reads, the PIRs of its context included', async () => {
    mocks.events = [];
    await listen();
    const topics = vi.mocked(pubSubAsyncIterator).mock.calls.at(-1)?.[0] as unknown as string[];
    expect(topics).toEqual(expect.arrayContaining([BUS_TOPICS[ENTITY_TYPE_PIR].EDIT_TOPIC]));
  });

  it('delivers nothing a subscriber may no longer receive, and closes the subscription when the client leaves', async () => {
    mocks.access = false;
    mocks.events = [{ instance: { id: 'incident-1' } }, { instance: buildRun() }];
    const iterator = await listen();
    expect((await iterator.next()).done).toBe(true);
    await iterator.return?.();
    expect(mocks.closed).toHaveBeenCalledTimes(1);
  });
});
