// noinspection NodeCoreCodingAssistance
import https from 'https';
// noinspection NodeCoreCodingAssistance
import http from 'http';
// noinspection NodeCoreCodingAssistance
import { readFileSync } from 'fs';
import conf, { logApp } from './config/conf';
import createApp from './app';
import createApolloServer from './graphql/graphql';
import { initBroadcaster } from './graphql/sseMiddleware';
import initExpiredManager from './manager/expiredManager';
import initTaskManager from './manager/taskManager';
import { isStrategyActivated, STRATEGY_CERT } from './config/providers';

const PORT = conf.get('app:port');
const REQ_TIMEOUT = conf.get('app:request_timeout');
const CERT_KEY_PATH = conf.get('app:https_cert:key');
const CERT_KEY_CERT = conf.get('app:https_cert:crt');
const CA_CERTS = conf.get('app:https_cert:ca');
const rejectUnauthorized = conf.get('app:https_cert:reject_unauthorized');
const broadcaster = initBroadcaster();
const expiredManager = initExpiredManager();
const taskManager = initTaskManager();
const createHttpServer = async () => {
  const apolloServer = createApolloServer();
  const { app, seeMiddleware } = await createApp(apolloServer, broadcaster);
  let httpServer;
  if (CERT_KEY_PATH && CERT_KEY_CERT) {
    const key = readFileSync(CERT_KEY_PATH);
    const cert = readFileSync(CERT_KEY_CERT);
    const ca = CA_CERTS.map((path) => readFileSync(path));
    const requestCert = isStrategyActivated(STRATEGY_CERT);
    httpServer = https.createServer({ key, cert, requestCert, rejectUnauthorized, ca }, app);
  } else {
    httpServer = http.createServer(app);
  }
  httpServer.setTimeout(REQ_TIMEOUT || 120000);
  apolloServer.installSubscriptionHandlers(httpServer);
  await broadcaster.start();
  await expiredManager.start();
  await taskManager.start();
  return { httpServer, seeMiddleware };
};

export const listenServer = async () => {
  return new Promise((resolve, reject) => {
    try {
      const serverPromise = createHttpServer();
      serverPromise.then(({ httpServer, seeMiddleware }) => {
        httpServer.on('close', () => {
          if (seeMiddleware) {
            seeMiddleware.shutdown();
          }
          expiredManager.shutdown();
          taskManager.shutdown();
        });
        httpServer.listen(PORT, () => {
          logApp.info(`[OPENCTI] Servers ready on port ${PORT}`);
          resolve(httpServer);
        });
      });
    } catch (e) {
      logApp.error(`[OPENCTI] Start http server fail`, { error: e });
      reject(e);
    }
  });
};
export const restartServer = async (httpServer) => {
  return new Promise((resolve, reject) => {
    httpServer.close(() => {
      logApp.info('[OPENCTI] GraphQL server stopped');
      listenServer()
        .then((server) => resolve(server))
        .catch((e) => reject(e));
    });
    httpServer.emit('close'); // force server close
  });
};
export const stopServer = async (httpServer) => {
  await broadcaster.shutdown();
  await expiredManager.shutdown();
  return new Promise((resolve) => {
    httpServer.close(() => {
      resolve();
    });
    httpServer.emit('close'); // force server close
  });
};

export default createHttpServer;
