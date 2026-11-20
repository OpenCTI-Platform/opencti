import { afterEach, describe, expect, it } from 'vitest';
import { promisify } from 'node:util';
import { setTimeout as wait } from 'node:timers/promises';
import SessionStoreMemory from '../../../src/database/sessionStore-memory';

const ONE_DAY = 86400000;
const SESSION_TIMEOUT = 1200000;

const buildSession = (userId: string, maxAge: number | null = SESSION_TIMEOUT) => ({
  cookie: { originalMaxAge: maxAge, maxAge, httpOnly: true, path: '/' },
  user: { id: userId, session_creation: '2026-01-01T00:00:00.000Z' },
});

type StoreSession = ReturnType<typeof buildSession> & { redis_key_id?: string; redis_key_ttl?: number };
type Callback<T> = (error: unknown, result?: T) => void;
type StoreMethod<A extends unknown[], T> = (...args: [...A, Callback<T>]) => void;

const stores: SessionStoreMemory[] = [];
const createStore = (options: { ttl?: number } = {}) => {
  const store = new SessionStoreMemory(options);
  stores.push(store);
  // the express-session store API is callback based, as used by the session middleware and the sessions management
  const call = <A extends unknown[], T>(method: StoreMethod<A, T>) => promisify(method.bind(store)) as (...args: A) => Promise<T>;
  return {
    store,
    get: call<[string], StoreSession | undefined>(store.get),
    set: call<[string, StoreSession], void>(store.set),
    touch: call<[string, StoreSession], void>(store.touch),
    destroy: call<[string], { sessionId: string; session?: StoreSession }>(store.destroy),
    all: call<[], StoreSession[]>(store.all),
    ids: call<[], string[]>(store.ids),
    clear: call<[], void>(store.clear),
    length: call<[], number>(store.length),
  };
};

afterEach(() => {
  stores.splice(0).forEach((store) => store.stopInterval());
});

describe('SessionStoreMemory', () => {
  it('should store and retrieve a session', async () => {
    const { get, set } = createStore();
    const session = buildSession('user-1');
    await set('sid-1', session);
    expect(await get('sid-1')).toEqual(session);
    expect(await get('unknown-sid')).toBeUndefined();
  });

  it('should expire the session after the cookie max age, in milliseconds', async () => {
    const { store, set } = createStore();
    await set('sid-1', buildSession('user-1'));
    const remainingTTL = store.store.getRemainingTTL('sid-1');
    expect(remainingTTL).toBeGreaterThan(SESSION_TIMEOUT - 1000);
    expect(remainingTTL).toBeLessThanOrEqual(SESSION_TIMEOUT);
  });

  it('should expire a session cookie after one day', async () => {
    const { store, set } = createStore();
    await set('sid-1', buildSession('user-1', null));
    const remainingTTL = store.store.getRemainingTTL('sid-1');
    expect(remainingTTL).toBeGreaterThan(ONE_DAY - 1000);
    expect(remainingTTL).toBeLessThanOrEqual(ONE_DAY);
  });

  it('should not return an expired session', async () => {
    const { get, set } = createStore({ ttl: 20 });
    await set('sid-1', buildSession('user-1'));
    expect(await get('sid-1')).toBeDefined();
    await wait(50);
    expect(await get('sid-1')).toBeUndefined();
  });

  it('should prune the expired sessions', async () => {
    const { store, set, length } = createStore({ ttl: 20 });
    await set('sid-1', buildSession('user-1'));
    expect(await length()).toBe(1);
    await wait(50);
    store.prune();
    expect(await length()).toBe(0);
  });

  it('should extend the session and update its cookie on touch', async () => {
    const { store, get, set, touch } = createStore();
    await set('sid-1', buildSession('user-1', 1000));
    const touchedSession = buildSession('user-1', SESSION_TIMEOUT);
    await touch('sid-1', touchedSession);
    expect((await get('sid-1'))?.cookie).toEqual(touchedSession.cookie);
    expect(store.store.getRemainingTTL('sid-1')).toBeGreaterThan(SESSION_TIMEOUT - 1000);
  });

  it('should not create a session on touch', async () => {
    const { get, touch } = createStore();
    await touch('sid-1', buildSession('user-1'));
    expect(await get('sid-1')).toBeUndefined();
  });

  it('should destroy the session and call back with it, like the redis store', async () => {
    const { get, set, destroy } = createStore();
    const session = buildSession('user-1');
    await set('sid-1', session);
    expect(await destroy('sid-1')).toEqual({ sessionId: 'sess:sid-1', session });
    expect(await get('sid-1')).toBeUndefined();
  });

  it('should call back when destroying an unknown session', async () => {
    const { destroy } = createStore();
    expect(await destroy('unknown-sid')).toEqual({ sessionId: 'sess:unknown-sid', session: undefined });
  });

  it('should list the sessions decorated like the redis store', async () => {
    const { all, set, ids } = createStore();
    await set('sid-1', buildSession('user-1'));
    await set('sid-2', buildSession('user-2'));
    const sessions = await all();
    expect(sessions).toHaveLength(2);
    const firstSession = sessions.find((s) => s.user.id === 'user-1');
    expect(firstSession?.redis_key_id).toBe('sess:sid-1');
    expect(firstSession?.redis_key_ttl).toBe(SESSION_TIMEOUT / 1000);
    expect(await ids()).toEqual(expect.arrayContaining(['sid-1', 'sid-2']));
  });

  it('should count and clear the sessions', async () => {
    const { set, clear, length } = createStore();
    await set('sid-1', buildSession('user-1'));
    await set('sid-2', buildSession('user-2'));
    expect(await length()).toBe(2);
    await clear();
    expect(await length()).toBe(0);
  });
});
