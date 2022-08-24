import channelTypeDefs from './event.graphql';
import convertEventToStix from './event-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import channelResolvers from './event-resolver';
import { ENTITY_TYPE_EVENT, StoreEntityEvent } from './event-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';

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
    { name: 'start_date', type: 'date', multiple: false, upsert: true },
    { name: 'end_date', type: 'date', multiple: false, upsert: true },
  ],
  relations: [],
  converter: convertEventToStix
};

registerDefinition(EVENT_DEFINITION);
