import { registerGraphqlSchema } from '../../graphql/schema';
import workspaceTypeDefs from './workspace.graphql';
import workspaceResolvers from './workspace-resolver';

registerGraphqlSchema({
  schema: workspaceTypeDefs,
  resolver: workspaceResolvers,
});
