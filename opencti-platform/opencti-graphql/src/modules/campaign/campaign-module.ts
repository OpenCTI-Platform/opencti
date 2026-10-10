import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_CAMPAIGN } from '../../schema/stixDomainObject';
import { campaignDefaultOverviewLayout } from './campaign';

const campaignModule: ModuleDescriptor = {
  id: 'campaign',
  overviewLayouts: [{ entityType: ENTITY_TYPE_CAMPAIGN, layout: campaignDefaultOverviewLayout }],
};

export default campaignModule;
