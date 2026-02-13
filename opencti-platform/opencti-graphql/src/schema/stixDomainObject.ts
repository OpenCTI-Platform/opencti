import {
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  ABSTRACT_STIX_META_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  ENTITY_TYPE_CONTAINER,
  ENTITY_TYPE_IDENTITY,
  ENTITY_TYPE_LOCATION,
  ENTITY_TYPE_THREAT_ACTOR,
} from './general';
import { ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_TAXII_COLLECTION, ENTITY_TYPE_WORK } from './internalObject';
import { aliases, type AttributeDefinition, xOpenctiAliases } from './attribute-definition';
import { ENTITY_TYPE_CONTAINER_CASE } from '../modules/case/case-types';
import { schemaTypesDefinition } from './schema-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../modules/case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_CONTAINER_CASE_RFT } from '../modules/case/case-rft/case-rft-types';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_DELETE_OPERATION } from '../modules/deleteOperation/deleteOperation-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from '../modules/securityPlatform/securityPlatform-types';

import { ENTITY_TYPE_CONTAINER_GROUPING } from '../modules/grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_FEEDBACK } from '../modules/case/feedback/feedback-types';

export const ATTRIBUTE_NAME = 'name';
export const ATTRIBUTE_ABSTRACT = 'attribute_abstract';
export const ATTRIBUTE_EXPLANATION = 'explanation';
export const ATTRIBUTE_DESCRIPTION = 'description';
export const ATTRIBUTE_DESCRIPTION_OPENCTI = 'x_opencti_description';
export const ATTRIBUTE_ALIASES = 'aliases';
export const ATTRIBUTE_ALIASES_OPENCTI = 'x_opencti_aliases';
export const ATTRIBUTE_ADDITIONAL_NAMES = 'x_opencti_additional_names';

export const ENTITY_TYPE_ATTACK_PATTERN = 'Attack-Pattern';
export const ENTITY_TYPE_CAMPAIGN = 'Campaign';
export const ENTITY_TYPE_CONTAINER_NOTE = 'Note';
export const ENTITY_TYPE_CONTAINER_OBSERVED_DATA = 'Observed-Data';
export const ENTITY_TYPE_CONTAINER_OPINION = 'Opinion';
export const ENTITY_TYPE_CONTAINER_REPORT = 'Report';
export const ENTITY_TYPE_COURSE_OF_ACTION = 'Course-Of-Action';
export const ENTITY_TYPE_IDENTITY_INDIVIDUAL = 'Individual';
export const ENTITY_TYPE_IDENTITY_SECTOR = 'Sector';
export const ENTITY_TYPE_IDENTITY_SYSTEM = 'System';
export const ENTITY_TYPE_INFRASTRUCTURE = 'Infrastructure';
export const ENTITY_TYPE_INTRUSION_SET = 'Intrusion-Set';
export const ENTITY_TYPE_LOCATION_CITY = 'City';
export const ENTITY_TYPE_LOCATION_COUNTRY = 'Country';
export const ENTITY_TYPE_LOCATION_REGION = 'Region';
export const ENTITY_TYPE_LOCATION_POSITION = 'Position';
export const ENTITY_TYPE_MALWARE = 'Malware';
export const ENTITY_TYPE_THREAT_ACTOR_GROUP = 'Threat-Actor-Group';
export const ENTITY_TYPE_TOOL = 'Tool';
export const ENTITY_TYPE_VULNERABILITY = 'Vulnerability';
export const ENTITY_TYPE_INCIDENT = 'Incident';
export const ENTITY_TYPE_DATA_COMPONENT = 'Data-Component';
export const ENTITY_TYPE_DATA_SOURCE = 'Data-Source';

export const ENTITY_TYPE_RESOLVED_FILTERS = 'Resolved-Filters';

export const STIX_DOMAIN_OBJECT_CONTAINER_CASES: Array<string> = [
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
  ENTITY_TYPE_CONTAINER_CASE_RFI,
  ENTITY_TYPE_CONTAINER_CASE_RFT,
];

const STIX_DOMAIN_OBJECT_CONTAINERS: Array<string> = [
  ...STIX_DOMAIN_OBJECT_CONTAINER_CASES,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_FEEDBACK,
  ENTITY_TYPE_CONTAINER_TASK,
];

schemaTypesDefinition.register(ENTITY_TYPE_CONTAINER, STIX_DOMAIN_OBJECT_CONTAINERS);
export const isStixDomainObjectContainer = (type: string): boolean => schemaTypesDefinition.isTypeIncludedIn(type, ENTITY_TYPE_CONTAINER)
  || type === ENTITY_TYPE_CONTAINER;

const STIX_DOMAIN_OBJECT_SHAREABLE_CONTAINERS: Array<string> = [
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_REPORT,
  ...STIX_DOMAIN_OBJECT_CONTAINER_CASES,
];
export const isStixDomainObjectShareableContainer = (type: string | null | undefined): boolean => {
  if (!type) return false;
  return STIX_DOMAIN_OBJECT_SHAREABLE_CONTAINERS.includes(type);
};

const STIX_DOMAIN_OBJECT_IDENTITIES: Array<string> = [
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
];
schemaTypesDefinition.register(ENTITY_TYPE_IDENTITY, STIX_DOMAIN_OBJECT_IDENTITIES);
export const isStixDomainObjectIdentity = (type: string): boolean => {
  return schemaTypesDefinition.isTypeIncludedIn(type, ENTITY_TYPE_IDENTITY) || type === ENTITY_TYPE_IDENTITY;
};

const STIX_DOMAIN_OBJECT_LOCATIONS: Array<string> = [
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_POSITION,
];
schemaTypesDefinition.register(ENTITY_TYPE_LOCATION, STIX_DOMAIN_OBJECT_LOCATIONS);
export const isStixDomainObjectLocation = (type: string): boolean => schemaTypesDefinition.isTypeIncludedIn(type, ENTITY_TYPE_LOCATION)
  || type === ENTITY_TYPE_LOCATION;

const STIX_DOMAIN_OBJECT_THREAT_ACTORS: Array<string> = [
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
];
schemaTypesDefinition.register(ENTITY_TYPE_THREAT_ACTOR, STIX_DOMAIN_OBJECT_THREAT_ACTORS);
export const isStixDomainObjectThreatActor = (type: string): boolean => schemaTypesDefinition.isTypeIncludedIn(type, ENTITY_TYPE_THREAT_ACTOR)
  || type === ENTITY_TYPE_THREAT_ACTOR;

export const STIX_DOMAIN_OBJECTS: Array<string> = [
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  ENTITY_TYPE_INCIDENT,
];
schemaTypesDefinition.register(ABSTRACT_STIX_DOMAIN_OBJECT, STIX_DOMAIN_OBJECTS);

export const isStixDomainObject = (type: string): boolean => {
  return schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_STIX_DOMAIN_OBJECT)
    || isStixDomainObjectIdentity(type)
    || isStixDomainObjectLocation(type)
    || isStixDomainObjectContainer(type)
    || isStixDomainObjectThreatActor(type)
    || type === ABSTRACT_STIX_DOMAIN_OBJECT;
};

export const isStixDomainObjectCase = (type: string): boolean => schemaTypesDefinition.isTypeIncludedIn(type, ENTITY_TYPE_CONTAINER_CASE)
  || type === ENTITY_TYPE_CONTAINER_CASE;

const STIX_DOMAIN_OBJECT_ALIASED: Array<string> = [
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_VULNERABILITY,
];
export const registerStixDomainAliased = (type: string) => {
  STIX_DOMAIN_OBJECT_ALIASED.push(type);
};
export const isStixObjectAliased = (type: string): boolean => {
  return STIX_DOMAIN_OBJECT_ALIASED.includes(type) || (isStixDomainObjectIdentity(type) && type !== ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM) || isStixDomainObjectLocation(type);
};

export const resolveAliasesField = (type: string): AttributeDefinition => {
  // eslint-disable-next-line max-len
  if (type === ENTITY_TYPE_COURSE_OF_ACTION || type === ENTITY_TYPE_VULNERABILITY || type === ENTITY_TYPE_CONTAINER_GROUPING || isStixDomainObjectIdentity(type) || isStixDomainObjectLocation(type)) {
    return xOpenctiAliases;
  }
  return aliases;
};

export const STIX_ORGANIZATIONS_UNRESTRICTED = [
  ABSTRACT_INTERNAL_OBJECT,
  ABSTRACT_INTERNAL_RELATIONSHIP,
  ABSTRACT_STIX_META_OBJECT,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_LOCATION,
  ENTITY_TYPE_WORK, // Work is defined as an history object
  ENTITY_TYPE_TAXII_COLLECTION, // TODO TaxiiCollection must be migrate to add according parent types
  ENTITY_TYPE_INTERNAL_FILE, // TODO InternalFile must be migrate to add according parent types
];

export const STIX_ORGANIZATIONS_RESTRICTED = [
  ENTITY_TYPE_DELETE_OPERATION, // deleted operations are internal objects but need to have organization restrictions applied
];
