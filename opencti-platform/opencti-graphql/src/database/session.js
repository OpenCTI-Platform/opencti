import session from 'express-session';
import nconf from 'nconf';
import * as R from 'ramda';
import conf, { booleanConf, OPENCTI_SESSION } from '../config/conf';
import SessionStoreMemory from './sessionStore-memory';
import RedisStore from './sessionStore-redis';
import { getSession, setSession } from './redis';

const sessionManager = nconf.get('app:session_manager');
const sessionSecret = nconf.get('app:session_secret') || nconf.get('app:admin:password');

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
const createSessionMiddleware = () => {
  const isRedisSession = sessionManager === 'shared';
  const store = isRedisSession ? createRedisSessionStore() : createMemorySessionStore();
  return {
    store,
    session: session({
      name: OPENCTI_SESSION,
      store,
      secret: sessionSecret,
      proxy: true,
      rolling: true,
      saveUninitialized: false,
      resave: false,
      cookie: {
        _expires: conf.get('app:session_timeout'),
        secure: booleanConf('app:https_cert:cookie_secure', false),
        sameSite: 'lax',
      },
    }),
  };
};

export const findSessions = () => {
  const { store } = applicationSession;
  return new Promise((accept) => {
    store.all((err, result) => {
      const sessionsPerUser = R.groupBy((s) => s.user.id, R.filter((n) => n.user, result));
      const sessions = Object.entries(sessionsPerUser).map(([k, v]) => {
        const userSessions = v.map((s) => {
          return {
            id: s.redis_key_id,
            created: s.user.session_creation,
            ttl: s.redis_key_ttl,
            originalMaxAge: Math.round(s.cookie.originalMaxAge / 1000)
          };
        });
        return { user_id: k, sessions: userSessions };
      });
      accept(sessions);
    });
  });
};

export const findUserSessions = async (userId) => {
  const sessions = await findSessions();
  const userSessions = sessions.filter((s) => s.user_id === userId);
  if (userSessions.length > 0) {
    return R.head(userSessions).sessions;
  }
  return [];
};

export const killSession = (id) => {
  const { store } = applicationSession;
  return new Promise((accept) => {
    store.destroy(id, () => {
      accept(id);
    });
  });
};

export const killUserSessions = async (userId) => {
  const sessions = await findUserSessions(userId);
  const sessionsIds = sessions.map((s) => s.id);
  for (let index = 0; index < sessionsIds.length; index += 1) {
    const sessionId = sessionsIds[index];
    await killSession(sessionId);
  }
  return sessionsIds;
};

export const markSessionForRefresh = async (id) => {
  const currentSession = await getSession(id);
  if (currentSession) {
    const newSession = { ...currentSession, session_refresh: true };
    await setSession(id, newSession, currentSession.expiration);
  }
  return undefined;
};

export const findSessionsForUsers = async (userIds) => {
  const sessions = await findSessions();
  return sessions.filter((s) => userIds.includes(s.user_id)).map((s) => s.sessions).flat();
};

export const applicationSession = createSessionMiddleware();
