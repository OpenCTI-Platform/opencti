import type { ModuleDescriptor } from '../../module-descriptor';
import { ENTITY_TYPE_INTERNAL_FILE } from '../../../schema/internalObject';
import { INTERNAL_FILE_ATTRIBUTES } from './document';

const documentModule: ModuleDescriptor = {
  id: 'document',
  attributes: [{ entityType: ENTITY_TYPE_INTERNAL_FILE, attributes: INTERNAL_FILE_ATTRIBUTES }],
};

export default documentModule;
