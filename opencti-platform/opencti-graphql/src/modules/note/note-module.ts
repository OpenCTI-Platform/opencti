import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_CONTAINER_NOTE } from '../../schema/stixDomainObject';
import { noteDefaultOverviewLayout } from './note';

const noteModule: ModuleDescriptor = {
  id: 'note',
  overviewLayouts: [{ entityType: ENTITY_TYPE_CONTAINER_NOTE, layout: noteDefaultOverviewLayout }],
};

export default noteModule;
