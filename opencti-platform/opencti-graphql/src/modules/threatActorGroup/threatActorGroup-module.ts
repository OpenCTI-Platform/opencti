import type { ModuleDescriptor } from '../module-descriptor';
import { ENTITY_TYPE_THREAT_ACTOR_GROUP } from '../../schema/stixDomainObject';
import { threatActorGroupDefaultOverviewLayout } from './threatActorGroup';

const threatActorGroupModule: ModuleDescriptor = {
  id: 'threatActorGroup',
  overviewLayouts: [{ entityType: ENTITY_TYPE_THREAT_ACTOR_GROUP, layout: threatActorGroupDefaultOverviewLayout }],
};

export default threatActorGroupModule;
