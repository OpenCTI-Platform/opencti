import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../schema/stixDomainObject';
import { reportDefaultOverviewLayout } from './report';

const reportModule: ModuleDescriptor = {
  id: 'report',
  overviewLayouts: [{ entityType: ENTITY_TYPE_CONTAINER_REPORT, layout: reportDefaultOverviewLayout }],
};

export default reportModule;
