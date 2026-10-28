import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../schema/stixDomainObject';
import { observedDataDefaultOverviewLayout } from './observedData';

const observedDataModule: ModuleDescriptor = {
  id: 'observedData',
  overviewLayouts: [{ entityType: ENTITY_TYPE_CONTAINER_OBSERVED_DATA, layout: observedDataDefaultOverviewLayout }],
};

export default observedDataModule;
