import { registerGraphqlSchema } from '../../graphql/schema';
import workspaceUserStateTypeDefs from './workspaceUserState.graphql';
import workspaceUserStateResolver from './workspaceUserState-resolver';

registerGraphqlSchema({
  schema: workspaceUserStateTypeDefs,
  resolver: workspaceUserStateResolver,
});
