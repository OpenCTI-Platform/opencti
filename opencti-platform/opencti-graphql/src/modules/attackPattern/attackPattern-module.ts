import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { attackPatternDefaultOverviewLayout } from './attackPattern';

const attackPatternModule: ModuleDescriptor = {
  id: 'attackPattern',
  overviewLayouts: [{ entityType: ENTITY_TYPE_ATTACK_PATTERN, layout: attackPatternDefaultOverviewLayout }],
};

export default attackPatternModule;
