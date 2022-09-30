import channelTypeDefs from './channel.graphql';
import convertChannelToStix from './channel-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { RELATION_BELONGS_TO, RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL
} from '../../schema/stixDomainObject';
import channelResolvers from './channel-resolver';
import { ENTITY_TYPE_CHANNEL, StoreEntityChannel } from './channel-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { ENTITY_TYPE_LANGUAGE } from '../language/language-types';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import {
  ENTITY_DOMAIN_NAME,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HOSTNAME, ENTITY_MEDIA_CONTENT,
  ENTITY_TEXT,
  ENTITY_URL, ENTITY_USER_ACCOUNT
} from '../../schema/stixCyberObservable';
import { REL_EXTENDED, REL_NEW } from '../../database/stix';

const RELATION_AMPLIFIES = 'amplifies';
const RELATION_PUBLISHES = 'publishes';

const CHANNEL_DEFINITION: ModuleDefinition<StoreEntityChannel> = {
  type: {
    id: 'channels',
    name: ENTITY_TYPE_CHANNEL,
    category: 'StixDomainEntity',
    aliased: true
  },
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
    { name: 'channel_types', type: 'string', multiple: true, upsert: true },
  ],
  relations: [
    { name: RELATION_TARGETS,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_SECTOR, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_EVENT, type: REL_EXTENDED },
      ] },
    { name: RELATION_USES,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LANGUAGE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_NARRATIVE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_EXTENDED },
        { name: ENTITY_TYPE_MALWARE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_TOOL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LANGUAGE, type: REL_EXTENDED },
      ] },
    { name: RELATION_PUBLISHES,
      targets: [
        { name: ENTITY_HASHED_OBSERVABLE_STIX_FILE, type: REL_NEW },
        { name: ENTITY_URL, type: REL_NEW },
        { name: ENTITY_TEXT, type: REL_NEW },
        { name: ENTITY_DOMAIN_NAME, type: REL_NEW },
        { name: ENTITY_HOSTNAME, type: REL_NEW },
        { name: ENTITY_MEDIA_CONTENT, type: REL_NEW },
      ] },
    { name: RELATION_AMPLIFIES,
      targets: [
        { name: ENTITY_TYPE_CHANNEL, type: REL_NEW },
      ] },
    { name: RELATION_BELONGS_TO,
      targets: [
        { name: ENTITY_USER_ACCOUNT, type: REL_EXTENDED },
      ] }
  ],
  converter: convertChannelToStix
};

registerDefinition(CHANNEL_DEFINITION);
