import { registerGraphqlSchema } from '../../graphql/schema';
import draftWorkspaceTypeDefs from './draftWorkspace.graphql';
import draftWorkspaceResolvers from './draftWorkspace-resolvers';

registerGraphqlSchema({
  schema: draftWorkspaceTypeDefs,
  resolver: draftWorkspaceResolvers,
});
