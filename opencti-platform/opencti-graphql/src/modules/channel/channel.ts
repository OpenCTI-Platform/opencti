import convertChannelToStix from './channel-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { RELATION_AMPLIFIES, RELATION_BELONGS_TO, RELATION_DELIVERS, RELATION_DROPS, RELATION_PUBLISHES, RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CHANNEL, type StixChannel, type StoreEntityChannel } from './channel-types';
import { ENTITY_TYPE_LANGUAGE } from '../language/language-types';
import { ENTITY_TYPE_NARRATIVE } from '../narrative/narrative-types';
import { ENTITY_TYPE_EVENT } from '../event/event-types';
import {
  ENTITY_DOMAIN_NAME,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HOSTNAME,
  ENTITY_MEDIA_CONTENT,
  ENTITY_TEXT,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT
} from '../../schema/stixCyberObservable';
import { REL_BUILT_IN, REL_EXTENDED, REL_NEW } from '../../database/stix';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';

export const CHANNEL_DEFINITION: ModuleDefinition<StoreEntityChannel, StixChannel> = {
  type: {
    id: 'channels',
    name: ENTITY_TYPE_CHANNEL,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: true
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
  overviewLayoutCustomization: [
    { key: 'details', width: 6, label: 'Entity details' },
    { key: 'basicInformation', width: 6, label: 'Basic information' },
    { key: 'latestCreatedRelationships', width: 6, label: 'Latest created relationships' },
    { key: 'latestContainers', width: 6, label: 'Latest containers' },
    { key: 'externalReferences', width: 6, label: 'External references' },
    { key: 'mostRecentHistory', width: 6, label: 'Most recent history' },
    { key: 'notes', width: 12, label: 'Notes about this entity' },
  ],
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'customizable', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'channel_types', label: 'Channel types', type: 'string', format: 'vocabulary', vocabularyCategory: 'channel_types_ov', mandatoryType: 'customizable', editDefault: true, multiple: true, upsert: true, isFilterable: true },
  ],
  relations: [
    {
      name: RELATION_TARGETS,
      targets: [
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_SECTOR, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_CITY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_COUNTRY, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_POSITION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LOCATION_REGION, type: REL_EXTENDED },
        { name: ENTITY_TYPE_EVENT, type: REL_EXTENDED },
        { name: ENTITY_TYPE_VULNERABILITY, type: REL_EXTENDED }
      ]
    },
    {
      name: RELATION_USES,
      targets: [
        { name: ENTITY_TYPE_INFRASTRUCTURE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_LANGUAGE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_NARRATIVE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_ATTACK_PATTERN, type: REL_EXTENDED },
        { name: ENTITY_TYPE_MALWARE, type: REL_EXTENDED },
        { name: ENTITY_TYPE_TOOL, type: REL_EXTENDED },
      ]
    },
    {
      name: RELATION_PUBLISHES,
      targets: [
        { name: ENTITY_HASHED_OBSERVABLE_STIX_FILE, type: REL_NEW },
        { name: ENTITY_URL, type: REL_NEW },
        { name: ENTITY_TEXT, type: REL_NEW },
        { name: ENTITY_DOMAIN_NAME, type: REL_NEW },
        { name: ENTITY_HOSTNAME, type: REL_NEW },
        { name: ENTITY_MEDIA_CONTENT, type: REL_NEW },
      ]
    },
    {
      name: RELATION_AMPLIFIES,
      targets: [
        { name: ENTITY_TYPE_CHANNEL, type: REL_NEW },
      ]
    },
    {
      name: RELATION_BELONGS_TO,
      targets: [
        { name: ENTITY_USER_ACCOUNT, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_INDIVIDUAL, type: REL_EXTENDED },
        { name: ENTITY_TYPE_IDENTITY_ORGANIZATION, type: REL_EXTENDED },
      ]
    },
    {
      name: RELATION_DELIVERS,
      targets: [
        { name: ENTITY_TYPE_MALWARE, type: REL_BUILT_IN },
      ]
    },
    {
      name: RELATION_DROPS,
      targets: [
        { name: ENTITY_TYPE_MALWARE, type: REL_EXTENDED },
      ]
    }
  ],
  relationsRefs: [
    objectOrganization
  ],
  representative: (stix: StixChannel) => {
    return stix.name;
  },
  converter: convertChannelToStix
};

registerDefinition(CHANNEL_DEFINITION);
