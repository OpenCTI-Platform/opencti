import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
} from '../../schema/stixDomainObject';
import {
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HOSTNAME,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_URL,
} from '../../schema/stixCyberObservable';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';

export const HUNT_TARGET_TYPES = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
];
export const HUNT_TECHNIQUE_TYPES = [ENTITY_TYPE_ATTACK_PATTERN];

/** Observables an indicator hunt looks up on a platform. */
export const HUNT_IOC_OBSERVABLE_TYPES = [
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_DOMAIN_NAME,
  ENTITY_HOSTNAME,
  ENTITY_URL,
  ENTITY_EMAIL_ADDR,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_MAC_ADDR,
];
/** Containers whose indicators and observables an indicator hunt looks for. */
export const HUNT_IOC_CONTAINER_TYPES = [ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_CONTAINER_GROUPING, ENTITY_TYPE_CONTAINER_CASE_INCIDENT];
/** Threats, tools and incidents whose indicators and observables an indicator hunt looks for. */
export const HUNT_IOC_SUBJECT_TYPES = [...HUNT_TARGET_TYPES, ENTITY_TYPE_TOOL, ENTITY_TYPE_INCIDENT];

// The intelligence a hunt is based on; for an indicator hunt, what it looks for: indicators and observables, and the
// entities whose indicators and observables it takes
export const HUNT_SOURCE_TYPES = [
  ENTITY_TYPE_INDICATOR,
  ...HUNT_IOC_OBSERVABLE_TYPES,
  ...HUNT_IOC_CONTAINER_TYPES,
  ...HUNT_IOC_SUBJECT_TYPES,
];
