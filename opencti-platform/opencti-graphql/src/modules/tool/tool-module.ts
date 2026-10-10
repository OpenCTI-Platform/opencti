import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_TOOL } from '../../schema/stixDomainObject';
import { toolDefaultOverviewLayout } from './tool';

const toolModule: ModuleDescriptor = {
  id: 'tool',
  overviewLayouts: [{ entityType: ENTITY_TYPE_TOOL, layout: toolDefaultOverviewLayout }],
};

export default toolModule;
