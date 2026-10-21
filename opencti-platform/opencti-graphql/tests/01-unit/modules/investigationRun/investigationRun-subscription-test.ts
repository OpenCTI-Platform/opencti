import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildRun } from './investigationRun-fixtures';

const mocks = vi.hoisted(() => ({
  run: null as unknown,
  access: true,
  // Published while the run is read for its sources, like a change made during the subscription setup.
  duringRead: [] as unknown[],
  topics: [] as string[],
  listeners: [] as Array<(event: unknown) => void>,
  unsubscribed: vi.fn(),
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
  loadInvestigationRun: vi.fn(async () => {
    mocks.duringRead.splice(0).forEach((event) => mocks.listeners.forEach((listener) => listener(event)));
    return mocks.run;
  }),
}));
vi.mock('../../../../src/graphql/subscriptionWrapper', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/graphql/subscriptionWrapper')>(),
  canSubscriberStillAccess: vi.fn(async () => mocks.access),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../src/database/redis')>(),
  // Resolves once subscribed, like the redis client: from then on every published event reaches the listener.
  pubSubSubscription: vi.fn(async (topic: string, onMessage: (event: unknown) => void) => {
    mocks.topics.push(topic);
    mocks.listeners.push(onMessage);
    return { topic, unsubscribe: mocks.unsubscribed };
  }),
}));

const { default: investigationRunResolvers } = await import('../../../../src/modules/investigationRun/investigationRun-resolvers');
const { BUS_TOPICS } = await import('../../../../src/config/conf');
const { ENTITY_TYPE_PIR } = await import('../../../../src/modules/pir/pir-types');

type Subscribe = (parent: unknown, args: { id: string }, context: unknown) => Promise<AsyncIterable<{ instance: { id: string } }>>;
const subscribe = (investigationRunResolvers.Subscription as unknown as { investigationRun: { subscribe: Subscribe } }).investigationRun.subscribe;
const listen = async () => (await subscribe(undefined, { id: 'run-1' }, { user: { id: 'user-1' } }))[Symbol.asyncIterator]();
// One listener per topic: an event is published on one of them.
const publish = (event: unknown) => mocks.listeners[0](event);

describe('Case Autopilot run subscription', () => {
  beforeEach(() => {
    mocks.run = buildRun();
    mocks.access = true;
    mocks.duringRead = [];
    mocks.topics = [];
    mocks.listeners = [];
    mocks.unsubscribed.mockClear();
  });

  it('delivers the run on its own events and when one of its sources changes, never on unrelated objects', async () => {
    const iterator = await listen();
    publish({ instance: { id: 'unrelated-entity' } });
    // A marking added to the investigated incident: the open view is served the run again.
    publish({ instance: { id: 'incident-1' } });
    publish({ instance: buildRun({ name: 'Renamed' }) });
    expect((await iterator.next()).value).toEqual({ instance: mocks.run });
    expect((await iterator.next()).value?.instance).toMatchObject({ id: 'run-1', name: 'Renamed' });
  });

  it('delivers the run for a source changed while its sources are read', async () => {
    mocks.duringRead = [{ instance: { id: 'incident-1' } }];
    const iterator = await listen();
    expect((await iterator.next()).value).toEqual({ instance: mocks.run });
  });

  it('follows the edits of every kind of source a run reads, the PIRs of its context included', async () => {
    await listen();
    expect(mocks.topics).toEqual(expect.arrayContaining([BUS_TOPICS[ENTITY_TYPE_PIR].EDIT_TOPIC]));
  });

  it('delivers nothing a subscriber may no longer receive, and closes the subscription when the client leaves', async () => {
    mocks.access = false;
    const iterator = await listen();
    const next = iterator.next();
    publish({ instance: { id: 'incident-1' } });
    publish({ instance: buildRun() });
    await iterator.return?.();
    expect((await next).done).toBe(true);
    expect(mocks.unsubscribed).toHaveBeenCalledTimes(mocks.topics.length);
  });
});
