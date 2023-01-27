// noinspection NodeCoreCodingAssistance
import https from 'https';
// noinspection NodeCoreCodingAssistance
import http from 'http';
// noinspection NodeCoreCodingAssistance
import { readFileSync } from 'fs';
import conf, { booleanConf, logApp } from '../config/conf';
import createApp from './httpPlatform';
import createApolloServer from '../graphql/graphql';
import { isStrategyActivated, STRATEGY_CERT } from '../config/providers';

const PORT = conf.get('app:port');
const REQ_TIMEOUT = conf.get('app:request_timeout');
const CERT_KEY_PATH = conf.get('app:https_cert:key');
const CERT_KEY_CERT = conf.get('app:https_cert:crt');
const CA_CERTS = conf.get('app:https_cert:ca');
const rejectUnauthorized = booleanConf('app:https_cert:reject_unauthorized', true);
const createHttpServer = async () => {
  const { app, seeMiddleware } = await createApp();
  // applyWildcard(app); // Needed in order to register prometheus metrics
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
  createApolloServer(app, httpServer);
  return { httpServer, seeMiddleware };
};

const listenServer = async () => {
  return new Promise((resolve, reject) => {
    try {
      const serverPromise = createHttpServer();
      serverPromise.then(({ httpServer, seeMiddleware }) => {
        httpServer.on('close', () => {
          seeMiddleware.shutdown();
        });
        httpServer.listen(PORT, () => {
          resolve(httpServer);
        });
      });
    } catch (e) {
      logApp.error(`[CYIO] API start fail`, { error: e });
      reject(e);
    }
  });
};

const stopServer = async (httpServer) => {
  return new Promise((resolve) => {
    httpServer.close(() => {
      resolve();
    });
    httpServer.emit('close'); // force server close
  });
};

const initHttpServer = () => {
  let server;
  return {
    start: async () => {
      server = await listenServer();
      // Handle hot module replacement resource dispose
      if (module.hot) {
        module.hot.dispose(async () => {
          await stopServer(server);
        });
      }
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
