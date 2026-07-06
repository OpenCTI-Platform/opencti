import https from 'node:https';
import http from 'node:http';
import graphqlUploadExpress from 'graphql-upload/graphqlUploadExpress.mjs';

import nconf from 'nconf';
import express from 'express';
import { expressMiddleware } from '@as-integrations/express5';
import { json } from 'body-parser';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { useServer } from 'graphql-ws/use/ws';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import passport from 'passport';
import conf, { basePath, booleanConf, loadCert, logApp, PORT } from '../config/conf';
import rateLimit from 'express-rate-limit';
import createApp from './httpPlatform';
import createApolloServer from '../graphql/graphql';
import { applicationSession } from '../database/session';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ForbiddenAccess, WorkNotALiveError } from '../config/errors';
import { getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { createAuthenticatedContext } from './httpAuthenticatedContext';
import { getSettings } from '../domain/settings';
import { isWorkAlive } from '../domain/work';
import { computeLoaders } from './httpAuthenticatedContext';
import { buildRateLimiterOptions } from './httpUtils';
import { checkDraftInContext } from './httpServer-draft';
import ipWhitelistMiddleware from './ipWhitelistMiddleware';

const MIN_20 = 20 * 60 * 1000;
const REQ_TIMEOUT = conf.get('app:request_timeout');
const CERT_KEY_PATH = conf.get('app:https_cert:key');
const CERT_KEY_CERT = conf.get('app:https_cert:crt');
const CA_CERTS = conf.get('app:https_cert:ca');
const rejectUnauthorized = booleanConf('app:https_cert:reject_unauthorized', true);

const graphqlMethodRestriction = (req, res, next) => {
  if (req.method === 'POST') {
    return next();
  }
  res.set('Allow', 'POST');
  return res.status(405).json({
    name: 'MethodNotAllowedError',
    message: 'Method Not Allowed. Use POST for GraphQL requests.',
  });
};

export const extractWsSessionContext = async (context) => {
  const req = context.extra.request;
  const webSocket = context.extra.socket;
  // This will be run every time the client sends a subscription request
  const wsSession = await new Promise((resolve) => {
    // use same session parser as normal gql queries
    const { session } = applicationSession;
    session(req, {}, () => {
      if (req.session) {
        resolve(req.session);
      }
      return false;
    });
  });
  // We have a good session. attach to context

  if (wsSession?.user) {
    const sessionContext = executionContext('api');
    const origin = {
      socket: 'subscription',
      ip: webSocket._socket.remoteAddress,
      user_id: wsSession.user?.id,
      group_ids: wsSession.user?.groups?.map((g) => g.internal_id) ?? [],
      organization_ids: wsSession.user?.organizations?.map((o) => o.internal_id) ?? [],
    };
    const platformUsers = await getEntitiesMapFromCache(sessionContext, SYSTEM_USER, ENTITY_TYPE_USER);
    const logged = platformUsers.get(wsSession?.user.id);
    sessionContext.user = { ...wsSession?.user, ...logged, origin };
    sessionContext.batch = computeLoaders(sessionContext, sessionContext.user);
    return sessionContext;
  }
  throw ForbiddenAccess('User must be authenticated');
};

const createHttpServer = async () => {
  logApp.info('[INIT] Configuring HTTP/HTTPS server');
  const app = express();
  // Rate limiter must be first registered so it applies to all requests including /graphql
  // Even before session so it avoid creating session on rate limited requests.
  app.use(rateLimit(buildRateLimiterOptions()));
  app.use(applicationSession.session);
  app.use(passport.initialize({}));
  const { schema, apolloServer } = createApolloServer();
  let httpServer;
  if (CERT_KEY_PATH && CERT_KEY_CERT) {
    try {
      logApp.info('[INIT] Configuring SSL for HTTPS server.');
      const key = loadCert(CERT_KEY_PATH);
      const cert = loadCert(CERT_KEY_CERT);
      const ca = CA_CERTS.map((path) => loadCert(path));
      const executeContext = executionContext('createHttpServer');
      const settings = await getSettings(executeContext);
      const requestCert = settings.cert_auth?.enabled;
      const passphrase = conf.get('app:https_cert:passphrase');
      const options = { key, cert, passphrase, requestCert, rejectUnauthorized, ca };
      httpServer = https.createServer(options, app);
      logApp.info('[INIT] HTTPS server initialization done.');
    } catch (e) {
      logApp.error('[INIT] HTTPS server cannot start, please verify app.https_cert and other configurations', { cause: e });
    }
  } else {
    httpServer = http.createServer(app);
    logApp.info('[INIT] HTTP server initialization done.');
  }
  httpServer.setTimeout(REQ_TIMEOUT || MIN_20);
  // subscriptionServer
  const wsServer = new WebSocketServer({
    server: httpServer,
    path: `${basePath}/graphql`,
  });
  wsServer.on('error', (e) => {
    throw e;
  });
  const serverCleanup = useServer({
    schema,
    context: extractWsSessionContext,
  }, wsServer);

  apolloServer.addPlugin(ApolloServerPluginDrainHttpServer({ httpServer }));
  apolloServer.addPlugin({
    async serverWillStart() {
      return {
        async drainServer() {
          await serverCleanup.dispose();
        },
        async renderLandingPage() {
          const html = `
            <!DOCTYPE html>
            <html>
            <head>
              <script>
                location.replace('${basePath}/public/graphql');
              </script>
            </head>
            </html>`;
          return { html };
        },
      };
    },
  });
  await apolloServer.start();

  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '50mb';
  app.use(express.json({ limit: requestSizeLimit }));
  // IP whitelist middleware — must be after session middleware to detect session-based auth
  app.use(`${basePath}/graphql`, ipWhitelistMiddleware);
  app.use(`${basePath}/graphql`, graphqlMethodRestriction);
  app.use((req, res, next) => {
    // Skip graphql-upload for chatbot routes (they handle multipart themselves via Busboy)
    if (req.path.startsWith(`${basePath}/chatbot/`)) {
      return next();
    }
    return graphqlUploadExpress()(req, res, next);
  });
  app.use(
    `${basePath}/graphql`,
    cors({ origin: basePath }),
    json(),
    expressMiddleware(apolloServer, {
      app,
      path: `${basePath}/graphql`,
      context: async ({ req, res }) => {
        const executeContext = await createAuthenticatedContext(req, res, 'api');
        // When context is related to a work, we need to check work status
        if (executeContext.workId) {
          const workStillAlive = await isWorkAlive(executeContext, executeContext.user, executeContext.workId);
          if (!workStillAlive) {
            throw WorkNotALiveError();
          }
        }
        await checkDraftInContext(executeContext);
        return executeContext;
      },
    }),
  );
  const { sseMiddleware } = await createApp(app, schema);
  return { httpServer, sseMiddleware };
};

const listenServer = async () => {
  return new Promise((resolve, reject) => {
    try {
      const serverPromise = createHttpServer();
      serverPromise.then(({ httpServer, sseMiddleware }) => {
        httpServer.on('close', () => {
          sseMiddleware.shutdown();
        });
        const server = httpServer.listen(PORT);
        resolve({ server });
      }).catch((reason) => {
        logApp.error('Http listen server error', { cause: reason });
      });
    } catch (e) {
      logApp.error('Http listen server fail', { cause: e });
      reject(e);
    }
  });
};

const stopServer = async ({ server }) => {
  return new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
    server.emit('close'); // force server close
  });
};

const initHttpServer = () => {
  let server;
  return {
    start: async () => {
      server = await listenServer();
    },
    shutdown: async () => {
      if (server) {
        await stopServer(server);
      }
    },
  };
};
const httpServer = initHttpServer();

export default httpServer;
