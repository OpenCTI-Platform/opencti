import channelTypeDefs from './channel.graphql';
import convertChannelToStix from './channel-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_THREAT_ACTOR
} from '../../schema/stixDomainObject';
import channelResolvers from './channel-resolver';
import { ENTITY_TYPE_CHANNEL, StoreEntityChannel } from './channel-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';

const CHANNEL_DEFINITION: ModuleDefinition<StoreEntityChannel> = {
  type: { name: ENTITY_TYPE_CHANNEL, category: 'StixDomainEntity', aliased: true },
  graphql: {
    schema: channelTypeDefs,
    resolver: channelResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_CHANNEL]: [{ src: NAME_FIELD }]
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
    { name: 'channel_type', type: 'string', multiple: false, upsert: true },
    // { name: 'channel_languages', type: 'string', multiple: true, upsert: true },
  ],
  relations: {
    sources: [
      // { name: 'published', type: 'StixCoreRelationship', targets: ['ENTITY_TYPE_CONTENT'] },
      { name: RELATION_TARGETS,
        type: 'StixCoreRelationship',
        targets: [ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_ORGANIZATION, ENTITY_TYPE_IDENTITY_SECTOR,
          ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_POSITION, ENTITY_TYPE_LOCATION_REGION] },
      { name: RELATION_USES, type: 'StixCoreRelationship', targets: [ENTITY_TYPE_INFRASTRUCTURE] },
      { name: 'amplifies', type: 'StixCoreRelationship', targets: [ENTITY_TYPE_CHANNEL] }
    ],
    targets: [
      { name: 'hosts', type: 'StixCoreRelationship', sources: [ENTITY_TYPE_INFRASTRUCTURE] },
      { name: 'controls', type: 'StixCoreRelationship', sources: [ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_ORGANIZATION] },
      { name: 'uses', type: 'StixCoreRelationship', sources: [ENTITY_TYPE_THREAT_ACTOR] },
      // is-amplified-by??
    ]
  },
  converter: convertChannelToStix
};

registerDefinition(CHANNEL_DEFINITION);
