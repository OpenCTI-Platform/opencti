import session from 'express-session';
import nconf from 'nconf';
import * as R from 'ramda';
import { createMemorySessionStore, createRedisSessionStore } from './redis';
import conf, { booleanConf, OPENCTI_SESSION } from '../config/conf';

let appSessionHandler;
const sessionManager = nconf.get('app:session_manager');
const sessionSecret = nconf.get('app:session_secret') || nconf.get('app:admin:password');

const createSessionMiddleware = () => {
  const isRedisSession = sessionManager === 'shared';
  const store = isRedisSession ? createRedisSessionStore() : createMemorySessionStore();
  return {
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
    store,
  };
};

export const initializeSession = () => {
  appSessionHandler = createSessionMiddleware();
  return appSessionHandler;
};

export const findSessions = () => {
  const { store } = applicationSession();
  return new Promise((accept) => {
    store.all((err, result) => {
      const sessionsPerUser = R.groupBy(
        (s) => s.user.id,
        R.filter((n) => n.user, result)
      );
      const sessions = Object.entries(sessionsPerUser).map(([k, v]) => {
        return {
          user_id: k,
          sessions: v.map((s) => ({ id: s.id, created: s.user.session_creation })),
        };
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

export const fetchSessionTtl = (id) => {
  const { store } = applicationSession();
  return new Promise((accept) => {
    store.expiration(id, (err, ttl) => {
      accept(ttl);
    });
  });
};

export const killSession = (id) => {
  const { store } = applicationSession();
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
  const { store } = applicationSession();
  return new Promise((resolve) => {
    store.get(id, (_, currentSession) => {
      const sessionObject = { ...currentSession, session_refresh: true };
      store.set(id, sessionObject, () => {
        resolve();
      });
    });
  });
};

export const findSessionsForUsers = async (userIds) => {
  const sessions = await findSessions();
  return sessions.filter((s) => userIds.includes(s.user_id)).map((s) => s.sessions).flat();
};

export const applicationSession = () => appSessionHandler;
