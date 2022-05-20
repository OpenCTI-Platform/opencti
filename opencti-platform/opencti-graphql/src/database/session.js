import session from 'express-session';
import nconf from 'nconf';
import { createMemorySessionStore, createRedisSessionStore } from './redis';
import conf, { booleanConf, OPENCTI_SESSION } from '../config/conf';

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

let appSessionHandler;
export const initializeSession = () => {
  appSessionHandler = createSessionMiddleware();
  return appSessionHandler;
};

export const applicationSession = () => appSessionHandler;
