import type { ModuleDescriptor } from '../module-descriptor';
import type { Resolvers } from '../../generated/graphql';
import { RETENTION_RULE_DEFINITION } from './retentionRules';
import retentionRulesTypeDefs from './retentionRules.graphql';
import retentionRulesResolver from './retentionRules-resolver';
import { RETENTION_MANAGER_DEFINITION } from '../../manager/retentionManager';

const retentionRulesModule: ModuleDescriptor = {
  id: 'retentionRules',
  dataModel: [RETENTION_RULE_DEFINITION],
  // TODO retentionRuleAdd resolves to a domain object that diverges from the generated graphql types,
  // which the untyped registerGraphqlSchema never checked.
  graphqlSchemas: [{ schema: retentionRulesTypeDefs, resolver: retentionRulesResolver as unknown as Resolvers }],
  managers: [RETENTION_MANAGER_DEFINITION],
};

export default retentionRulesModule;
