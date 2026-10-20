import { registerGraphqlSchema } from '../../graphql/schema';
import ingestionHealthTypeDefs from './ingestionHealth.graphql';

// Types only: the health fields are resolved on the entities that carry them (connectors)
registerGraphqlSchema({
  schema: ingestionHealthTypeDefs,
  resolver: {},
});
