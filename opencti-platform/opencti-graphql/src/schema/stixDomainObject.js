import * as R from 'ramda';
import {
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
  REL_INDEX_PREFIX,
} from './general';
import {
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
} from './stixMetaRelationship';

export const ATTRIBUTE_ALIASES = 'aliases';
export const ATTRIBUTE_ALIASES_OPENCTI = 'x_opencti_aliases';

export const ENTITY_TYPE_ATTACK_PATTERN = 'Attack-Pattern';
export const ENTITY_TYPE_CAMPAIGN = 'Campaign';
export const ENTITY_TYPE_CONTAINER_NOTE = 'Note';
export const ENTITY_TYPE_CONTAINER_OBSERVED_DATA = 'Observed-Data';
export const ENTITY_TYPE_CONTAINER_OPINION = 'Opinion';
export const ENTITY_TYPE_CONTAINER_REPORT = 'Report';
export const ENTITY_TYPE_COURSE_OF_ACTION = 'Course-Of-Action';
export const ENTITY_TYPE_IDENTITY_INDIVIDUAL = 'Individual';
export const ENTITY_TYPE_IDENTITY_ORGANIZATION = 'Organization';
export const ENTITY_TYPE_IDENTITY_SECTOR = 'Sector';
export const ENTITY_TYPE_INDICATOR = 'Indicator';
export const ENTITY_TYPE_INFRASTRUCTURE = 'Infrastructure';
export const ENTITY_TYPE_INTRUSION_SET = 'Intrusion-Set';
export const ENTITY_TYPE_LOCATION_CITY = 'City';
export const ENTITY_TYPE_LOCATION_COUNTRY = 'Country';
export const ENTITY_TYPE_LOCATION_REGION = 'Region';
export const ENTITY_TYPE_LOCATION_POSITION = 'Position';
export const ENTITY_TYPE_MALWARE = 'Malware';
export const ENTITY_TYPE_THREAT_ACTOR = 'Threat-Actor';
export const ENTITY_TYPE_TOOL = 'Tool';
export const ENTITY_TYPE_VULNERABILITY = 'Vulnerability';
export const ENTITY_TYPE_X_OPENCTI_INCIDENT = 'X-OpenCTI-Incident';

const STIX_DOMAIN_OBJECT_CONTAINERS = [
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
];
export const isStixDomainObjectContainer = (type) =>
  R.includes(type, STIX_DOMAIN_OBJECT_CONTAINERS) || type === ENTITY_TYPE_CONTAINER;

const STIX_DOMAIN_OBJECT_IDENTITIES = [
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
];
export const isStixDomainObjectIdentity = (type) =>
  R.includes(type, STIX_DOMAIN_OBJECT_IDENTITIES) || type === ENTITY_TYPE_IDENTITY;

const STIX_DOMAIN_OBJECT_LOCATIONS = [
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_POSITION,
];
export const isStixDomainObjectLocation = (type) =>
  R.includes(type, STIX_DOMAIN_OBJECT_LOCATIONS) || type === ENTITY_TYPE_LOCATION;

const STIX_DOMAIN_OBJECTS = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  ENTITY_TYPE_X_OPENCTI_INCIDENT,
];
export const isStixDomainObject = (type) =>
  R.includes(type, STIX_DOMAIN_OBJECTS) ||
  isStixDomainObjectIdentity(type) ||
  isStixDomainObjectLocation(type) ||
  isStixDomainObjectContainer(type) ||
  type === ABSTRACT_STIX_DOMAIN_OBJECT;

const STIX_DOMAIN_OBJECT_ALIASED = [
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_X_OPENCTI_INCIDENT,
];
export const isStixObjectAliased = (type) =>
  R.includes(type, STIX_DOMAIN_OBJECT_ALIASED) || isStixDomainObjectIdentity(type) || isStixDomainObjectLocation(type);
export const resolveAliasesField = (type) => {
  if (type === ENTITY_TYPE_COURSE_OF_ACTION || isStixDomainObjectIdentity(type) || isStixDomainObjectLocation(type)) {
    return ATTRIBUTE_ALIASES_OPENCTI;
  }
  return ATTRIBUTE_ALIASES;
};

export const stixDomainObjectOptions = {
  StixDomainObjectsOrdering: {
    objectMarking: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    objectLabel: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  StixDomainObjectsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    objectContains: `${REL_INDEX_PREFIX}${RELATION_OBJECT}.internal_id`,
    hasExternalReference: `${REL_INDEX_PREFIX}${RELATION_EXTERNAL_REFERENCE}.internal_id`,
    indicates: `${REL_INDEX_PREFIX}indicates.internal_id`,
  },
};

export const stixDomainObjectFieldsToBeUpdated = {
  [ENTITY_TYPE_ATTACK_PATTERN]: [
    'description',
    'x_mitre_platforms',
    'x_mitre_permissions_required',
    'x_mitre_detection',
  ],
  [ENTITY_TYPE_CAMPAIGN]: ['description', 'first_seen', 'last_seen'],
  [ENTITY_TYPE_CONTAINER_NOTE]: ['description'],
  [ENTITY_TYPE_CONTAINER_OBSERVED_DATA]: ['description'],
  [ENTITY_TYPE_CONTAINER_OPINION]: ['description'],
  [ENTITY_TYPE_CONTAINER_REPORT]: ['description'],
  [ENTITY_TYPE_COURSE_OF_ACTION]: ['description'],
  [ENTITY_TYPE_IDENTITY_INDIVIDUAL]: ['description'],
  [ENTITY_TYPE_IDENTITY_ORGANIZATION]: ['description'],
  [ENTITY_TYPE_IDENTITY_SECTOR]: ['description'],
  [ENTITY_TYPE_INDICATOR]: ['description'],
  [ENTITY_TYPE_INFRASTRUCTURE]: ['description'],
  [ENTITY_TYPE_INTRUSION_SET]: [
    'description',
    'first_seen',
    'last_seen',
    'goals',
    'resource_level',
    'primary_motivation',
    'secondary_motivations',
  ],
  [ENTITY_TYPE_LOCATION_CITY]: ['description', 'latitude', 'longitude'],
  [ENTITY_TYPE_LOCATION_COUNTRY]: ['description', 'latitude', 'longitude'],
  [ENTITY_TYPE_LOCATION_REGION]: ['description', 'latitude', 'longitude'],
  [ENTITY_TYPE_LOCATION_POSITION]: ['description', 'latitude', 'longitude'],
  [ENTITY_TYPE_MALWARE]: ['description', 'is_family', 'malware_types'],
  [ENTITY_TYPE_THREAT_ACTOR]: [
    'description',
    'first_seen',
    'last_seen',
    'goals',
    'resource_level',
    'primary_motivation',
    'secondary_motivations',
  ],
  [ENTITY_TYPE_TOOL]: ['description'],
  [ENTITY_TYPE_VULNERABILITY]: ['description'],
  [ENTITY_TYPE_X_OPENCTI_INCIDENT]: ['description'],
};
