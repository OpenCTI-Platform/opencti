import https from 'node:https';
import http from 'node:http';
import graphqlUploadExpress from 'graphql-upload/graphqlUploadExpress.mjs';
// eslint-disable-next-line import/extensions
import nconf from 'nconf';
import express from 'express';
import { expressMiddleware } from '@apollo/server/express4';
import { json } from 'body-parser';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { useServer } from 'graphql-ws/lib/use/ws';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import passport from 'passport/lib';
import conf, { basePath, booleanConf, isFeatureEnabled, loadCert, logApp, PORT } from '../config/conf';
import createApp from './httpPlatform';
import createApolloServer from '../graphql/graphql';
import { isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { applicationSession } from '../database/session';
import { executionContext } from '../utils/access';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { UnknownError } from '../config/errors';

const MIN_20 = 20 * 60 * 1000;
const REQ_TIMEOUT = conf.get('app:request_timeout');
const CERT_KEY_PATH = conf.get('app:https_cert:key');
const CERT_KEY_CERT = conf.get('app:https_cert:crt');
const CA_CERTS = conf.get('app:https_cert:ca');
const rejectUnauthorized = booleanConf('app:https_cert:reject_unauthorized', true);

const createHttpServer = async () => {
  logApp.info('[INIT] Configuring HTTP/HTTPS server');
  const app = express();
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
      const requestCert = isStrategyActivated(STRATEGY_CERT);
      const passphrase = conf.get('app:https_cert:passphrase');
      const options = { key, cert, passphrase, requestCert, rejectUnauthorized, ca };
      httpServer = https.createServer(options, app);
      logApp.info('[INIT] HTTPS server initialization done.');
    } catch (e) {
      logApp.error('[INIT] HTTPS server cannot start, please verify app.https_cert and other configurations', e);
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
    throw new Error(e.message);
  });
  const serverCleanup = useServer({
    schema,
    context: async (ctx) => {
      const req = ctx.extra.request;
      const webSocket = ctx.extra.socket;
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
        const context = executionContext('api');
        const origin = {
          socket: 'subscription',
          ip: webSocket._socket.remoteAddress,
          user_id: wsSession.user?.id,
          group_ids: wsSession.user?.group_ids,
          organization_ids: wsSession.user?.organizations?.map((o) => o.internal_id) ?? [],
        };
        context.user = { ...wsSession.user, origin };
        return context;
      }
      throw new Error('User must be authenticated');
    },
  }, wsServer);
  apolloServer.addPlugin(ApolloServerPluginDrainHttpServer({ httpServer }));
  apolloServer.addPlugin({
    async serverWillStart() {
      return {
        async drainServer() {
          serverCleanup.dispose();
        },
      };
    },
  });
  await apolloServer.start();
  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '50mb';
  app.use(express.json({ limit: requestSizeLimit }));
  app.use(graphqlUploadExpress());
  app.use(
    `${basePath}/graphql`,
    cors({ origin: basePath }),
    json(),
    expressMiddleware(apolloServer, {
      app,
      path: `${basePath}/graphql`,
      context: async ({ req, res }) => {
        const executeContext = executionContext('api');
        executeContext.req = req;
        executeContext.res = res;
        executeContext.workId = req.headers['opencti-work-id']; // Api call comes from a worker processing
        if (isFeatureEnabled('DRAFT_WORKSPACE')) {
          executeContext.draft_context = req.headers['opencti-draft-id']; // Api call is to be made is specific draft context
        }
        executeContext.eventId = req.headers['opencti-event-id']; // Api call is due to listening event
        executeContext.previousStandard = req.headers['previous-standard']; // Previous standard id
        executeContext.synchronizedUpsert = req.headers['synchronized-upsert'] === 'true'; // If full sync needs to be done
        try {
          const user = await authenticateUserFromRequest(executeContext, req, res);
          if (user) {
            if (isFeatureEnabled('DRAFT_WORKSPACE') && !executeContext.draft_context) {
              executeContext.draft_context = user.draft_context;
            }
            executeContext.user = userWithOrigin(req, user);
          }
        } catch (error) {
          logApp.error(error);
        }
        return executeContext;
      }
    })
  );
  const { sseMiddleware } = await createApp(app);
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
      });
    } catch (e) {
      logApp.error(UnknownError('Http listen server fail', { cause: e }));
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
