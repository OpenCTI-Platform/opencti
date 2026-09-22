import session from 'express-session';
import nconf from 'nconf';
import { promisify } from 'node:util';
import conf, { booleanConf, OPENCTI_SESSION } from '../config/conf';
import SessionStoreMemory from './sessionStore-memory';
import RedisStore from './sessionStore-redis';
import { getPlatformCrypto } from '../utils/platformCrypto';
import { memoize } from '../utils/memoize';

const sessionManager = nconf.get('app:session_manager');

// The session cookie signing key is derived from the platform encryption key.
// It is then automatically shared between all the platform nodes and does not rely on any user provided secret.
const getSessionSecret = async () => {
  const factory = await getPlatformCrypto();
  return factory.deriveSecret(['session', 'signature'], 1);
};

const createMemorySessionStore = () => {
  return new SessionStoreMemory({
    checkPeriod: 3600000, // prune expired entries every 1h
  });
};
const createRedisSessionStore = () => {
  return new RedisStore({
    ttl: conf.get('app:session_timeout'),
  });
};
const createApplicationSession = async () => {
  const isRedisSession = sessionManager === 'shared';
  const store = isRedisSession ? createRedisSessionStore() : createMemorySessionStore();
  const isSessionCookie = conf.get('app:session_cookie') ?? false;
  const sessionTimeout = isSessionCookie ? undefined : conf.get('app:session_timeout');
  return {
    // The store API is callback based and gives a full read/write access to every user session:
    // only the promisified operations needed by this module are exposed.
    sessionStore: {
      prefix: store.prefix,
      // the store interface allows an array or an object of sessions, depending on the implementation
      all: async () => Object.values(await promisify(store.all.bind(store))()),
      destroy: promisify(store.destroy.bind(store)),
    },
    session: session({
      name: OPENCTI_SESSION,
      store,
      secret: await getSessionSecret(),
      proxy: true,
      rolling: true,
      saveUninitialized: false,
      resave: false,
      cookie: {
        _expires: sessionTimeout,
        secure: booleanConf('app:https_cert:cookie_secure', false),
        sameSite: conf.get('app:https_cert:cookie_samesite') ?? 'lax',
      },
    }),
  };
};

const getApplicationSession = memoize(createApplicationSession);

const getSessionStore = async () => (await getApplicationSession()).sessionStore;

export const getSessionMiddleware = async () => (await getApplicationSession()).session;

export const findSessions = async () => {
  const store = await getSessionStore();
  const storeSessions = await store.all();
  const sessionsPerUser = Object.groupBy(storeSessions.filter((s) => s.user), (s) => s.user.id);
  return Object.entries(sessionsPerUser).map(([userId, userStoreSessions]) => {
    const userSessions = userStoreSessions.map((s) => {
      return {
        id: s.redis_key_id,
        created: s.user.session_creation,
        ttl: s.redis_key_ttl,
        originalMaxAge: Math.round(s.cookie.originalMaxAge / 1000),
      };
    });
    return { user_id: userId, sessions: userSessions };
  });
};

export const findUserSessions = async (userId) => {
  const sessions = await findSessions();
  const userSessions = sessions.find((s) => s.user_id === userId);
  return userSessions?.sessions ?? [];
};

// Session ids are exposed with the store prefix, it must be removed before reaching the store
export const killSession = async (sessionId) => {
  const store = await getSessionStore();
  return store.destroy(sessionId.split(store.prefix)[1]);
};

const killSessions = async (sessionsIds) => {
  const killedSessions = [];
  for (let index = 0; index < sessionsIds.length; index += 1) {
    const killedSession = await killSession(sessionsIds[index]);
    killedSessions.push(killedSession);
  }
  return killedSessions;
};

export const killUserSessions = async (userId) => {
  const sessions = await findUserSessions(userId);
  const sessionsIds = sessions.map((s) => s.id);
  return killSessions(sessionsIds);
};

// Kill every session of a user but the current one, the current session id being the raw store id
export const killOtherUserSessions = async (userId, currentSessionId) => {
  if (!currentSessionId) {
    return;
  }
  const sessions = await findUserSessions(userId);
  const otherSessionsIds = sessions.filter((s) => !s.id.endsWith(currentSessionId)).map((s) => s.id);
  await killSessions(otherSessionsIds);
};

// Kill the oldest sessions of a user to leave room for a new one, according to the given concurrent
// sessions limit. Returns the number of killed sessions.
export const killUserSessionsOverLimit = async (userId, maxConcurrentSessions) => {
  if (!maxConcurrentSessions || maxConcurrentSessions <= 0) {
    return 0;
  }
  const sessions = await findUserSessions(userId);
  if (sessions.length < maxConcurrentSessions) {
    return 0;
  }
  const oldestSessionsFirst = [...sessions].sort((a, b) => {
    if (a.created < b.created) {
      return -1;
    }
    if (a.created > b.created) {
      return 1;
    }
    return 0;
  });
  const sessionsToKill = oldestSessionsFirst.slice(0, sessions.length - maxConcurrentSessions + 1);
  await killSessions(sessionsToKill.map((s) => s.id));
  return sessionsToKill.length;
};
