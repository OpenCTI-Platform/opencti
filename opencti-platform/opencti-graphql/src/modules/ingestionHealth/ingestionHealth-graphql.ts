import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';
import ingestionHealthResolvers from './ingestionHealth-resolvers';

// The health fields are resolved on the entities that carry them (connectors, feeds and syncs), see ingestionHealthFieldResolvers
registerGraphqlSchema({
  schema: ingestionHealthTypeDefs,
  resolver: ingestionHealthResolvers,
});
