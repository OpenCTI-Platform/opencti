import type { ModuleDescriptor } from '../module-descriptor';
import { WORKSPACE_DEFINITION } from './workspace';
import workspaceTypeDefs from './workspace.graphql';
import workspaceResolvers from './workspace-resolver';

const workspaceModule: ModuleDescriptor = {
  id: 'workspace',
  dataModel: [WORKSPACE_DEFINITION],
  graphqlSchemas: [{ schema: workspaceTypeDefs, resolver: workspaceResolvers }],
};

export default workspaceModule;
