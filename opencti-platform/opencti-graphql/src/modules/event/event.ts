import channelTypeDefs from './event.graphql';
import convertEventToStix from './event-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import channelResolvers from './event-resolver';
import { ENTITY_TYPE_EVENT, StoreEntityEvent } from './event-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { RELATION_LOCATED_AT } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION
} from '../../schema/stixDomainObject';

const EVENT_DEFINITION: ModuleDefinition<StoreEntityEvent> = {
  type: {
    id: 'events',
    name: ENTITY_TYPE_EVENT,
    category: 'StixDomainEntity',
    aliased: true
  },
  graphql: {
    schema: channelTypeDefs,
    resolver: channelResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_EVENT]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', type: 'string', multiple: false, upsert: true },
    { name: 'description', type: 'string', multiple: false, upsert: true },
    { name: 'event_types', type: 'string', multiple: true, upsert: true },
    { name: 'start_time', type: 'date', multiple: false, upsert: true },
    { name: 'stop_time', type: 'date', multiple: false, upsert: true },
  ],
  relations: [
    { name: RELATION_LOCATED_AT,
      type: 'StixCoreRelationship',
      targets: [ENTITY_TYPE_LOCATION_REGION, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_POSITION] }
  ],
  converter: convertEventToStix
};

registerDefinition(EVENT_DEFINITION);
