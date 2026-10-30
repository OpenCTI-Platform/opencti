import { afterEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

// Two distinct valid encryption keys (32 bytes, base64 encoded)
const ENCRYPTION_KEY_1 = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';
const ENCRYPTION_KEY_2 = 'ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=';

// Session store shared by all the simulated nodes, as the Redis store is in a cluster deployment.
// The session signature key is then the only thing that can prevent a node from resuming a session.
const sharedSessions = vi.hoisted(() => new Map<string, string>());
vi.mock('../../../src/database/sessionStore-memory', async (importOriginal) => {
  const { default: SessionStoreMemory } = await importOriginal<any>();
  class SharedSessionStore extends SessionStoreMemory {
    prefix = 'sess:';

    constructor(options = {}) {
      super(options);
      this.stopInterval(); // pruning is useless, entries are kept in the shared map
    }

    get(sid: string, fn: (error?: unknown, session?: unknown) => void) {
      const data = sharedSessions.get(sid);
      return data ? fn(null, JSON.parse(data)) : fn();
    }

    all(fn: (error: unknown, sessions: unknown[]) => void) {
      // the redis store decorates the sessions with their store key and ttl
      const sessions = [...sharedSessions.entries()].map(([sid, data]) => ({
        ...JSON.parse(data),
        redis_key_id: `sess:${sid}`,
        redis_key_ttl: 1200,
      }));
      return fn(null, sessions);
    }

    set(sid: string, sess: unknown, fn: () => void) {
      sharedSessions.set(sid, JSON.stringify(sess));
      return fn();
    }

    destroy(sid: string, fn: () => void) {
      sharedSessions.delete(sid);
      return fn();
    }

    touch(sid: string, sess: unknown, fn: () => void) {
      return this.set(sid, sess, fn);
    }
  }
  return { default: SharedSessionStore };
});

type SessionUser = { id: string };
type SessionRequest = { sessionID: string; session: { user?: SessionUser } };
type CallResult = { sessionId: string; user: SessionUser | null };

const sessionRequest = (req: express.Request) => req as unknown as SessionRequest;

// Simulate a platform node: the module registry is reset so the session middleware is built again
// with the given encryption key, exactly as it is on another node or after a restart.
const loadSessionModule = async (encryptionKey: string = ENCRYPTION_KEY_1) => {
  vi.resetModules();
  process.env.APP__ENCRYPTION_KEY = encryptionKey;
  process.env.APP__SESSION_MANAGER = 'local';
  return import('../../../src/database/session');
};

const startNode = async (encryptionKey: string) => {
  const { getSessionMiddleware } = await loadSessionModule(encryptionKey);
  const session = await getSessionMiddleware();

  const app = express();
  app.use(session);
  app.get('/login', (req, res) => {
    const { session: userSession, sessionID } = sessionRequest(req);
    userSession.user = { id: 'user-id' };
    res.json({ sessionId: sessionID, user: userSession.user });
  });
  app.get('/me', (req, res) => {
    const { session: userSession, sessionID } = sessionRequest(req);
    res.json({ sessionId: sessionID, user: userSession.user ?? null });
  });

  const server = http.createServer(app);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;

  const call = async (path: string, cookie?: string) => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { headers: cookie ? { cookie } : {} });
    const body = await response.json() as CallResult;
    return { ...body, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  };

  const stop = async () => {
    server.close();
    await once(server, 'close');
  };

  return { call, stop };
};

describe('session: signature key derived from the platform encryption key', () => {
  const nodes: Awaited<ReturnType<typeof startNode>>[] = [];
  const startTrackedNode = async (encryptionKey: string) => {
    const node = await startNode(encryptionKey);
    nodes.push(node);
    return node;
  };

  afterEach(async () => {
    await Promise.all(nodes.splice(0).map((node) => node.stop()));
    sharedSessions.clear();
    delete process.env.APP__ENCRYPTION_KEY;
    delete process.env.APP__SESSION_MANAGER;
  });

  it('should keep the session on the node that created it', async () => {
    const node = await startTrackedNode(ENCRYPTION_KEY_1);

    const login = await node.call('/login');
    expect(login.cookie).toBeDefined();

    const me = await node.call('/me', login.cookie);
    expect(me.sessionId).toEqual(login.sessionId);
    expect(me.user).toEqual({ id: 'user-id' });
  });

  it('should resume the session on another node using the same encryption key', async () => {
    const firstNode = await startTrackedNode(ENCRYPTION_KEY_1);
    const secondNode = await startTrackedNode(ENCRYPTION_KEY_1);

    const login = await firstNode.call('/login');
    const me = await secondNode.call('/me', login.cookie);

    expect(me.sessionId).toEqual(login.sessionId);
    expect(me.user).toEqual({ id: 'user-id' });
  });

  it('should reject a session cookie signed with another encryption key', async () => {
    const firstNode = await startTrackedNode(ENCRYPTION_KEY_1);
    const secondNode = await startTrackedNode(ENCRYPTION_KEY_2);

    const login = await firstNode.call('/login');
    const me = await secondNode.call('/me', login.cookie);

    // The signature is rejected, so a brand new session is created and the user has to authenticate again
    expect(me.sessionId).not.toEqual(login.sessionId);
    expect(me.user).toBeNull();
  });
});

describe('session: user sessions management', () => {
  const seedSession = (storeSessionId: string, userId: string, creation: string) => {
    const storedSession = { user: { id: userId, session_creation: creation }, cookie: { originalMaxAge: 1200000 } };
    sharedSessions.set(storeSessionId, JSON.stringify(storedSession));
  };

  afterEach(() => {
    sharedSessions.clear();
    delete process.env.APP__ENCRYPTION_KEY;
    delete process.env.APP__SESSION_MANAGER;
  });

  it('should kill the oldest sessions of a user over the concurrent sessions limit', async () => {
    const { killUserSessionsOverLimit, findUserSessions } = await loadSessionModule();
    seedSession('oldest', 'user-1', '2026-01-01T10:00:00.000Z');
    seedSession('middle', 'user-1', '2026-01-01T11:00:00.000Z');
    seedSession('newest', 'user-1', '2026-01-01T12:00:00.000Z');
    seedSession('other-user', 'user-2', '2026-01-01T09:00:00.000Z');

    // one more session is about to be created, so only one of the three existing sessions can be kept
    expect(await killUserSessionsOverLimit('user-1', 2)).toEqual(2);

    expect((await findUserSessions('user-1')).map((s: { id: string }) => s.id)).toEqual(['sess:newest']);
    expect(await findUserSessions('user-2')).toHaveLength(1);
  });

  it('should keep the sessions of a user under the concurrent sessions limit', async () => {
    const { killUserSessionsOverLimit, findUserSessions } = await loadSessionModule();
    seedSession('first', 'user-1', '2026-01-01T10:00:00.000Z');

    expect(await killUserSessionsOverLimit('user-1', 3)).toEqual(0);
    expect(await findUserSessions('user-1')).toHaveLength(1);
  });

  it('should keep every session when the concurrent sessions limit is disabled', async () => {
    const { killUserSessionsOverLimit, findUserSessions } = await loadSessionModule();
    seedSession('first', 'user-1', '2026-01-01T10:00:00.000Z');
    seedSession('second', 'user-1', '2026-01-01T11:00:00.000Z');

    expect(await killUserSessionsOverLimit('user-1', 0)).toEqual(0);
    expect(await killUserSessionsOverLimit('user-1', null)).toEqual(0);
    expect(await findUserSessions('user-1')).toHaveLength(2);
  });

  it('should kill every session of a user but the current one', async () => {
    const { killOtherUserSessions, findUserSessions } = await loadSessionModule();
    seedSession('current', 'user-1', '2026-01-01T10:00:00.000Z');
    seedSession('another', 'user-1', '2026-01-01T11:00:00.000Z');
    seedSession('other-user', 'user-2', '2026-01-01T09:00:00.000Z');

    await killOtherUserSessions('user-1', 'current');

    expect((await findUserSessions('user-1')).map((s: { id: string }) => s.id)).toEqual(['sess:current']);
    expect(await findUserSessions('user-2')).toHaveLength(1);
  });

  it('should keep every session when the current session is unknown', async () => {
    const { killOtherUserSessions, findUserSessions } = await loadSessionModule();
    seedSession('first', 'user-1', '2026-01-01T10:00:00.000Z');
    seedSession('second', 'user-1', '2026-01-01T11:00:00.000Z');

    await killOtherUserSessions('user-1', undefined);

    expect(await findUserSessions('user-1')).toHaveLength(2);
  });
});
