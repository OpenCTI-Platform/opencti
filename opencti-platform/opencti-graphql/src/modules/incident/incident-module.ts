import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_INCIDENT } from '../../schema/stixDomainObject';
import { incidentDefaultOverviewLayout } from './incident';

const incidentModule: ModuleDescriptor = {
  id: 'incident',
  overviewLayouts: [{ entityType: ENTITY_TYPE_INCIDENT, layout: incidentDefaultOverviewLayout }],
};

export default incidentModule;
