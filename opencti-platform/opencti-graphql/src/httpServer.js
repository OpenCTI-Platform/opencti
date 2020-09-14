import http from 'http';
import conf, { logger } from './config/conf';
import createApp from './app';
import createApolloServer from './graphql/graphql';

const PORT = conf.get('app:port');

const createHttpServer = async () => {
  const apolloServer = createApolloServer();
  const { app, seeMiddleware } = await createApp(apolloServer);
  const httpServer = http.createServer(app);
  apolloServer.installSubscriptionHandlers(httpServer);
  return { httpServer, seeMiddleware };
};

export const listenServer = async () => {
  return new Promise((resolve, reject) => {
    try {
      const serverPromise = createHttpServer();
      serverPromise.then(({ httpServer, seeMiddleware }) => {
        httpServer.on('close', () => {
          seeMiddleware.shutdown();
        });
        httpServer.listen(PORT, () => {
          logger.info(`OPENCTI Ready on port ${PORT}`);
          resolve(httpServer);
        });
      });
    } catch (e) {
      logger.error(`[OPENCTI] Start http server fail`, { error: e });
      reject(e);
    }
  });
};
export const restartServer = (httpServer) => {
  return new Promise((resolve, reject) => {
    httpServer.close(() => {
      logger.info('OPENCTI server stopped');
      listenServer()
        .then((server) => resolve(server))
        .catch((e) => reject(e));
    });
    httpServer.emit('close'); // force server close
  });
};

export const stopServer = (httpServer) => {
  return new Promise((resolve) => {
    httpServer.close(() => {
      resolve();
    });
    httpServer.emit('close'); // force server close
  });
};

export default createHttpServer;
