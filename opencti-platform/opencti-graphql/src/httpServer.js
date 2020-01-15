import http from 'http';
import { isAppRealTime } from './config/conf';
import createApp from './app';
import createApolloServer from './graphql/graphql';

const createHttpServer = () => {
  const apolloServer = createApolloServer();
  const app = createApp(apolloServer);
  const httpServer = http.createServer(app);
  if (isAppRealTime) {
    apolloServer.installSubscriptionHandlers(httpServer);
  }
  return httpServer;
};

export default createHttpServer;
