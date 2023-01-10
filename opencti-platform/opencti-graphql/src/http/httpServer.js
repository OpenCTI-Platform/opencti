import https from 'node:https';
import http from 'node:http';
import graphqlUploadExpress from 'graphql-upload/graphqlUploadExpress.mjs';
import { readFileSync } from 'node:fs';
import { SubscriptionServer } from 'subscriptions-transport-ws';
// eslint-disable-next-line import/extensions
import { execute, subscribe } from 'graphql/index.js';
import nconf from 'nconf';
import express from 'express';
import conf, { basePath, booleanConf, logApp, PORT } from '../config/conf';
import createApp from './httpPlatform';
import createApolloServer from '../graphql/graphql';
import { isStrategyActivated, STRATEGY_CERT } from '../config/providers';
import { applicationSession } from '../database/session';
import { checkSystemDependencies } from '../initialization';
import { executionContext } from '../utils/access';

const MIN_20 = 20 * 60 * 1000;
const REQ_TIMEOUT = conf.get('app:request_timeout');
const CERT_KEY_PATH = conf.get('app:https_cert:key');
const CERT_KEY_CERT = conf.get('app:https_cert:crt');
const CA_CERTS = conf.get('app:https_cert:ca');
const rejectUnauthorized = booleanConf('app:https_cert:reject_unauthorized', true);

const onHealthCheck = () => checkSystemDependencies();

const createHttpServer = async () => {
  const app = express();
  app.use(applicationSession.session);
  const { schema, apolloServer } = createApolloServer();
  let httpServer;
  if (CERT_KEY_PATH && CERT_KEY_CERT) {
    const key = readFileSync(CERT_KEY_PATH);
    const cert = readFileSync(CERT_KEY_CERT);
    const ca = CA_CERTS.map((path) => readFileSync(path));
    const requestCert = isStrategyActivated(STRATEGY_CERT);
    const passphrase = conf.get('app:https_cert:passphrase');
    const options = { key, cert, passphrase, requestCert, rejectUnauthorized, ca };
    httpServer = https.createServer(options, app);
  } else {
    httpServer = http.createServer(app);
  }
  httpServer.setTimeout(REQ_TIMEOUT || MIN_20);
  // subscriptionServer
  const subscriptionServer = SubscriptionServer.create(
    {
      schema,
      execute,
      subscribe,
      async onConnect(connectionParams, webSocket) {
        const wsSession = await new Promise((resolve) => {
          // use same session parser as normal gql queries
          const { session } = applicationSession;
          session(webSocket.upgradeReq, {}, () => {
            if (webSocket.upgradeReq.session) {
              resolve(webSocket.upgradeReq.session);
            }
            return false;
          });
        });
        // We have a good session. attach to context
        if (wsSession.user) {
          const context = executionContext('api');
          context.user = wsSession.user;
          return context;
        }
        throw new Error('User must be authenticated');
      },
    },
    {
      server: httpServer,
      path: `${basePath}${apolloServer.graphqlPath}`,
    }
  );
  apolloServer.plugins.push({
    async serverWillStart() {
      return {
        async drainServer() {
          subscriptionServer.close();
        },
      };
    },
  });
  await apolloServer.start();
  const requestSizeLimit = nconf.get('app:max_payload_body_size') || '50mb';
  app.use(graphqlUploadExpress());
  apolloServer.applyMiddleware({
    app,
    cors: true,
    bodyParserConfig: { limit: requestSizeLimit },
    onHealthCheck,
    path: `${basePath}/graphql`,
  });
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
      logApp.error('[OPENCTI] API start fail', { error: e });
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
