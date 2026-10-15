import type { ModuleDescriptor } from '../../module-descriptor';
import { INTERNAL_FILE_DEFINITION } from './document';

const documentModule: ModuleDescriptor = {
  id: 'document',
  dataModel: [INTERNAL_FILE_DEFINITION],
};

export default documentModule;
