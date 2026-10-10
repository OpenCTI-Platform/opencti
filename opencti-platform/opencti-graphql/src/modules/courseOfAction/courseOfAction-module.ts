import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_COURSE_OF_ACTION } from '../../schema/stixDomainObject';
import { courseOfActionDefaultOverviewLayout } from './courseOfAction';

const courseOfActionModule: ModuleDescriptor = {
  id: 'courseOfAction',
  overviewLayouts: [{ entityType: ENTITY_TYPE_COURSE_OF_ACTION, layout: courseOfActionDefaultOverviewLayout }],
};

export default courseOfActionModule;
