import type { ModuleDescriptor } from '../module-descriptor';
import { RETENTION_RULE_DEFINITION } from './retentionRules';
import retentionRulesTypeDefs from './retentionRules.graphql';
import retentionRulesResolver from './retentionRules-resolver';
import { RETENTION_MANAGER_DEFINITION } from '../../manager/retentionManager';

const retentionRulesModule: ModuleDescriptor = {
  id: 'retentionRules',
  dataModel: [RETENTION_RULE_DEFINITION],
  graphqlSchemas: [{ schema: retentionRulesTypeDefs, resolver: retentionRulesResolver }],
  managers: [RETENTION_MANAGER_DEFINITION],
};

export default retentionRulesModule;
