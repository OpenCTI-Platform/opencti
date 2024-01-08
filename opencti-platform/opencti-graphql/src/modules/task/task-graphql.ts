import { registerGraphqlSchema } from '../../graphql/schema';
import taskTypeDefs from './task.graphql';
import taskResolvers from './task-resolvers';

registerGraphqlSchema({
  schema: taskTypeDefs,
  resolver: taskResolvers,
});
