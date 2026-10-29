import type { ModuleDescriptor } from '../../module-descriptor';
import { XTM_ONE_REGISTRATION_MANAGER_DEFINITION } from '../../../manager/xtmOneRegistrationManager';

const xtmOneModule: ModuleDescriptor = {
  id: 'xtmOne',
  // Only a manager: no data model nor graphql schema of its own
  managers: [XTM_ONE_REGISTRATION_MANAGER_DEFINITION],
};

export default xtmOneModule;
