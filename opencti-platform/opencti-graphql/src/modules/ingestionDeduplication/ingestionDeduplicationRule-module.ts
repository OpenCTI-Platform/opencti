import type { ModuleDescriptor } from '../module-descriptor';
import { INGESTION_DEDUPLICATION_RULE_DEFINITION } from './ingestionDeduplicationRule';
import ingestionDeduplicationRuleTypeDefs from './ingestionDeduplicationRule.graphql';
import ingestionDeduplicationRuleResolvers from './ingestionDeduplicationRule-resolver';

const ingestionDeduplicationRuleModule: ModuleDescriptor = {
  id: 'ingestionDeduplicationRule',
  dataModel: [INGESTION_DEDUPLICATION_RULE_DEFINITION],
  graphqlSchemas: [{ schema: ingestionDeduplicationRuleTypeDefs, resolver: ingestionDeduplicationRuleResolvers }],
};

export default ingestionDeduplicationRuleModule;
