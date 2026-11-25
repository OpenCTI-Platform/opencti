import { describe, expect, it } from 'vitest';
import SessionStoreMemory from '../../../src/database/sessionStore-memory';

const destroy = (store: SessionStoreMemory, sid: string) => new Promise<{ sessionId: string; session?: unknown; deleted: boolean }>((resolve, reject) => {
  store.destroy(sid, (error: unknown, result: { sessionId: string; session?: unknown; deleted: boolean }) => (error ? reject(error) : resolve(result)));
});

// The session is put in the cache directly, as the store would save it
const set = (store: SessionStoreMemory, sid: string, session: unknown) => {
  store.store.set(sid, JSON.stringify(session));
};

describe('SessionStoreMemory destroy', () => {
  it('should delete the session and call back with it', async () => {
    const store = new SessionStoreMemory();
    set(store, 'sid', { user: { id: 'user-id' }, cookie: {} });

    const result = await destroy(store, 'sid');

    expect(result).toEqual({ sessionId: 'sid', session: { user: { id: 'user-id' }, cookie: {} }, deleted: true });
    expect(store.store.has('sid')).toBe(false);
  });

  it('should tell only the first call that it deleted the session', async () => {
    const store = new SessionStoreMemory();
    set(store, 'sid', { user: { id: 'user-id' }, cookie: {} });

    const results = await Promise.all([destroy(store, 'sid'), destroy(store, 'sid')]);

    expect(results.map((r) => r.deleted)).toEqual([true, false]);
  });

  it('should call back for a session that does not exist', async () => {
    const store = new SessionStoreMemory();
    expect(await destroy(store, 'unknown')).toEqual({ sessionId: 'unknown', session: undefined, deleted: false });
  });
});
