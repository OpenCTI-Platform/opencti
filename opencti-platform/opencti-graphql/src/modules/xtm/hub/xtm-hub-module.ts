import type { ModuleDescriptor } from '../../module-descriptor';
import xtmHubTypeDefs from './xtm-hub.graphql';
import xtmHubResolvers from './xtm-hub-resolver';
import { HUB_REGISTRATION_MANAGER_DEFINITION } from '../../../manager/hubRegistrationManager';

const xtmHubModule: ModuleDescriptor = {
  id: 'xtmHub',
  graphqlSchemas: [{ schema: xtmHubTypeDefs, resolver: xtmHubResolvers }],
  managers: [HUB_REGISTRATION_MANAGER_DEFINITION],
};

export default xtmHubModule;
