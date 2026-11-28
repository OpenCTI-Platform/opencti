import type { ModuleDescriptor } from '../module-descriptor';
import { DRAFT_WORKSPACE_DEFINITION } from './draftWorkspace';
import draftWorkspaceTypeDefs from './draftWorkspace.graphql';
import draftWorkspaceResolvers from './draftWorkspace-resolvers';

const draftWorkspaceModule: ModuleDescriptor = {
  id: 'draftWorkspace',
  dataModel: [DRAFT_WORKSPACE_DEFINITION],
  graphqlSchemas: [{ schema: draftWorkspaceTypeDefs, resolver: draftWorkspaceResolvers }],
};

export default draftWorkspaceModule;
