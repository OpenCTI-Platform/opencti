import session from 'express-session';
import nconf from 'nconf';
import * as R from 'ramda';
import conf, { booleanConf, OPENCTI_SESSION } from '../config/conf';
import SessionStoreMemory from './sessionStore-memory';
import RedisStore from './sessionStore-redis';
import { getSession } from './redis';
import { MAX_EVENT_LOOP_PROCESSING_TIME } from './utils';

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
  const isSessionCookie = conf.get('app:session_cookie') ?? false;
  const sessionTimeout = isSessionCookie ? undefined : conf.get('app:session_timeout');
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
        _expires: sessionTimeout,
        secure: booleanConf('app:https_cert:cookie_secure', false),
        sameSite: conf.get('app:https_cert:cookie_samesite') ?? 'lax',
      },
    }),
  };
};

export const findSessions = async (maxInactivityDurationInMin = 1) => {
  const { store } = applicationSession;
  const fetchedSessions = await new Promise((accept, reject) => {
    store.all((err, result) => {
      if (err) {
        reject(err);
      } else {
        accept(result);
      }
    });
  });
  const preparedSessions = {};
  let startProcessingTime = new Date().getTime();
  for (let index = 0; index < fetchedSessions.length; index += 1) {
    const s = fetchedSessions[index];
    const currentUserId = s.user.impersonate_user_id ?? s.user.id;
    const data = {
      id: s.redis_key_id,
      user_execution_id: currentUserId !== s.user.id ? s.user.id : undefined,
      created: s.user.session_creation,
      ttl: s.redis_key_ttl,
      originalMaxAge: Math.round(s.cookie.originalMaxAge / 1000)
    };
    const isActiveSession = (s.cookie.originalMaxAge / 1000 - s.redis_key_ttl) / 60 < maxInactivityDurationInMin;
    if (preparedSessions[currentUserId]) {
      preparedSessions[currentUserId].total += 1;
      preparedSessions[currentUserId].isActiveUser = preparedSessions[currentUserId].isActiveUser || isActiveSession;
      if (preparedSessions[currentUserId].sessions.length < 10) {
        preparedSessions[currentUserId].sessions.push(data);
      }
    } else {
      preparedSessions[currentUserId] = { sessions: [data], total: 1, isActiveUser: isActiveSession };
    }
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
  const sessions = [];
  const refEntries = Object.entries(preparedSessions);
  for (let indexRef = 0; indexRef < refEntries.length; indexRef += 1) {
    const [user_id, data] = refEntries[indexRef];
    sessions.push({ user_id, ...data });
  }
  return sessions;
};

// return the list of users ids that have a session activ in the last maxInactivityDuration min
export const usersWithActiveSessionCount = async (maxInactivityDurationInMin = 1) => {
  const sessions = await findSessions(maxInactivityDurationInMin);
  return sessions.filter((s) => s.isActiveUser).length;
};

export const findUserSessions = async (userId) => {
  const sessions = await findSessions();
  const userSessions = sessions.filter((s) => s.user_id === userId);
  if (userSessions.length > 0) {
    return R.head(userSessions).sessions;
  }
  return [];
};

export const killSession = async (id) => {
  const { store } = applicationSession;
  return new Promise((accept) => {
    store.destroy(id, (_, data) => {
      accept(data);
    });
  });
};

export const killUserSessions = async (userId) => {
  const { store } = applicationSession;
  const sessions = await findUserSessions(userId);
  const sessionsIds = sessions.map((s) => s.id);
  const killedSessions = [];
  for (let index = 0; index < sessionsIds.length; index += 1) {
    const sessionId = sessionsIds[index];
    const sessId = sessionId.split(store.prefix)[1];
    const killedSession = await killSession(sessId);
    killedSessions.push(killedSession);
  }
  return killedSessions;
};

export const markSessionForRefresh = async (id) => {
  const { store } = applicationSession;
  const currentSession = await getSession(id);
  if (currentSession) {
    const newSession = { ...currentSession, session_refresh: true };
    const sessId = id.includes(store.prefix) ? id.split(store.prefix)[1] : id;
    store.set(sessId, newSession); // this will ensure the session is updated in the cache
    // TODO check what to do with currentSession.expiration
    // await setSession(id, newSession, currentSession.expiration);
  }
  return undefined;
};

export const markAllSessionsForRefresh = async () => {
  const sessions = (await findSessions()).map((s) => s.sessions).flat();
  await Promise.all(sessions.map((s) => markSessionForRefresh(s.id)));
};

export const findSessionsForUsers = async (userIds) => {
  const sessions = await findSessions();
  return sessions.filter((s) => userIds.includes(s.user_id)).map((s) => s.sessions).flat();
};

export const applicationSession = createSessionMiddleware();
