import session from 'express-session';
import nconf from 'nconf';
import { promisify } from 'node:util';
import conf, { booleanConf, OPENCTI_SESSION } from '../config/conf';
import SessionStoreMemory from './sessionStore-memory';
import RedisStore from './sessionStore-redis';
import { getPlatformCrypto } from '../utils/platformCrypto';
import { memoize } from '../utils/memoize';
import { ConfigurationError } from '../config/errors';

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
      get: promisify(store.get.bind(store)),
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

// Highest value of a GraphQL Int, the type the maximum lifetime is exposed with in the platform settings
const MAX_SESSION_MAX_LIFETIME = 2147483647;

// Maximum lifetime of a session in ms, counted from the login and never extended by the user activity.
// 0 (the default) means no limit, as an unset or empty value does (an empty environment variable is common in
// deployment templates). Any other value that is not a whole number of ms in range makes the platform refuse
// to start (see boot): falling back to no limit would silently disable a security setting.
export const getSessionMaxLifetime = () => {
  const configuredValue = conf.get('app:session_max_lifetime');
  if (configuredValue === undefined || configuredValue === null || configuredValue === '') {
    return 0;
  }
  // Environment values are parsed (true, false, [] ...): only a number or a string of digits is a lifetime,
  // as converting anything else to a number would give a meaningless limit (true is 1 ms, false is no limit)
  const isNumericValue = typeof configuredValue === 'number' || (typeof configuredValue === 'string' && /^\d+$/.test(configuredValue));
  const maxLifetime = isNumericValue ? Number(configuredValue) : NaN;
  if (!Number.isInteger(maxLifetime) || maxLifetime < 0 || maxLifetime > MAX_SESSION_MAX_LIFETIME) {
    throw ConfigurationError(
      `Invalid app:session_max_lifetime: expected a whole number of milliseconds between 0 (no limit) and ${MAX_SESSION_MAX_LIFETIME}`,
      { value: configuredValue },
    );
  }
  return maxLifetime;
};

const getApplicationSession = memoize(createApplicationSession);

// A session over its maximum lifetime must be ended, whatever the activity of its user.
// A session without a valid login time cannot prove its age: it is ended as well when a limit is set.
export const isSessionOverMaxLifetime = (sessionUser, maxLifetime = getSessionMaxLifetime(), nowTime = Date.now()) => {
  if (maxLifetime <= 0) {
    return false;
  }
  const loginTime = Date.parse(sessionUser?.session_creation ?? '');
  if (Number.isNaN(loginTime)) {
    return true;
  }
  return nowTime - loginTime >= maxLifetime;
};

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

// Raw session ids, as given by req.sessionID, directly reach the store
export const findSessionByRawId = async (rawSessionId) => {
  const store = await getSessionStore();
  return store.get(rawSessionId);
};

export const killSessionByRawId = async (rawSessionId) => {
  const store = await getSessionStore();
  return store.destroy(rawSessionId);
};

// Delete a session, returning true only for the call that actually deleted it. When several requests
// (possibly on several nodes) end the same session at once, a single one of them gets true.
export const endSessionByRawId = async (rawSessionId) => {
  const killed = await killSessionByRawId(rawSessionId);
  return killed?.deleted === true;
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
