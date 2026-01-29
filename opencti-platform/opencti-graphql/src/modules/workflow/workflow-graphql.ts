import { registerGraphqlSchema } from '../../graphql/schema';
import workflowTypeDefs from './workflow.graphql';
import workflowResolvers from './workflow-resolvers';

registerGraphqlSchema({
  schema: workflowTypeDefs,
  resolver: workflowResolvers,
});
