import { registerGraphqlSchema } from '../../graphql/schema';
import dataSourceTypeDefs from './dataSource.graphql';
import dataSourceResolvers from './dataSource-resolvers';

registerGraphqlSchema({
  schema: dataSourceTypeDefs,
  resolver: dataSourceResolvers,
});
