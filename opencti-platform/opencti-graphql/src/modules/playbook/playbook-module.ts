import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_PLAYBOOK_DEFINITION } from './playbook';
import entityPlaybookTypeDefs from './playbook.graphql';
import entityPlaybookResolvers from './playbook-resolvers';

const playbookModule: ModuleDescriptor = {
  id: 'playbook',
  dataModel: [ENTITY_PLAYBOOK_DEFINITION],
  graphqlSchemas: [{ schema: entityPlaybookTypeDefs, resolver: entityPlaybookResolvers }],
};

export default playbookModule;
