import { getConnectorProxyConfiguration } from '../domain/connector-proxy';
import type { AuthContext } from '../types/user';

const connectorProxyResolvers = {
  Query: {
    connectorProxyConfiguration: (_: any, __: any, context: AuthContext) => {
      if (!context.user) {
        throw new Error('User context is required');
      }
      return getConnectorProxyConfiguration(context, context.user);
    }
  }
};

export default connectorProxyResolvers;
