import { registerGraphqlSchema } from '../../graphql/schema';
import eventTypeDefs from './event.graphql';
import eventResolvers from './event-resolver';

registerGraphqlSchema({
  schema: eventTypeDefs,
  resolver: eventResolvers,
});
