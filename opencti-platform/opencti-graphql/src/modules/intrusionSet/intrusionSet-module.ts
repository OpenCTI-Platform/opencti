import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_INTRUSION_SET } from '../../schema/stixDomainObject';
import { intrusionSetDefaultOverviewLayout } from './intrusionSet';

const intrusionSetModule: ModuleDescriptor = {
  id: 'intrusionSet',
  overviewLayouts: [{ entityType: ENTITY_TYPE_INTRUSION_SET, layout: intrusionSetDefaultOverviewLayout }],
};

export default intrusionSetModule;
