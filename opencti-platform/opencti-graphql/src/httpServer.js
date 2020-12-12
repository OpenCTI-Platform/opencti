// noinspection NodeCoreCodingAssistance
import http from 'http';
import conf, { logger } from './config/conf';
import createApp from './app';
import createApolloServer from './graphql/graphql';
import { initBroadcaster } from './graphql/sseMiddleware';

const PORT = conf.get('app:port');
const broadcaster = initBroadcaster();
const createHttpServer = async () => {
  const apolloServer = createApolloServer();
  const { app, seeMiddleware } = await createApp(apolloServer, broadcaster);
  const httpServer = http.createServer(app);
  apolloServer.installSubscriptionHandlers(httpServer);
  await broadcaster.start();
  return { httpServer, seeMiddleware };
};

export const listenServer = async () => {
  return new Promise((resolve, reject) => {
    try {
      const serverPromise = createHttpServer();
      serverPromise.then(({ httpServer, seeMiddleware }) => {
        httpServer.on('close', () => {
          if (seeMiddleware) seeMiddleware.shutdown();
        });
        httpServer.listen(PORT, () => {
          logger.info(`[OPENCTI] Servers ready on port ${PORT}`);
          resolve(httpServer);
        });
      });
    } catch (e) {
      logger.error(`[OPENCTI] Start http server fail`, { error: e });
      reject(e);
    }
  });
};
export const restartServer = async (httpServer) => {
  return new Promise((resolve, reject) => {
    httpServer.close(() => {
      logger.info('[OPENCTI] GraphQL server stopped');
      listenServer()
        .then((server) => resolve(server))
        .catch((e) => reject(e));
    });
    httpServer.emit('close'); // force server close
  });
};
export const stopServer = async (httpServer) => {
  await broadcaster.shutdown();
  return new Promise((resolve) => {
    httpServer.close(() => {
      resolve();
    });
    httpServer.emit('close'); // force server close
  });
};

export default createHttpServer;
