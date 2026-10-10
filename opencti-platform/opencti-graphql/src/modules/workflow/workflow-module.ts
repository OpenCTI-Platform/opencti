import type { ModuleDescriptor } from '../module-descriptor';
import type { Resolvers } from '../../generated/graphql';
import { ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { WORKFLOW_DEFINITION_DEFINITION } from './storage/workflow-definition-entity';
import { WORKFLOW_INSTANCE_DEFINITION } from './storage/workflow-instance-entity';
import workflowTypeDefs from './api/workflow.graphql';
import workflowResolvers from './api/workflow-resolvers';
import { WORKFLOW_STATUS_CLEANUP_MANAGER_DEFINITION } from '../../manager/workflowStatusCleanupManager';

const workflowModule: ModuleDescriptor = {
  id: 'workflow',
  dataModel: [WORKFLOW_DEFINITION_DEFINITION, WORKFLOW_INSTANCE_DEFINITION],
  // TODO the Container resolvers diverge from the generated graphql types,
  // which the untyped registerGraphqlSchema never checked.
  graphqlSchemas: [{ schema: workflowTypeDefs, resolver: workflowResolvers as unknown as Resolvers }],
  managers: isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG) ? [WORKFLOW_STATUS_CLEANUP_MANAGER_DEFINITION] : [],
};

export default workflowModule;
