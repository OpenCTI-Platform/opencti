import * as R from 'ramda';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE, schemaTypes } from './general';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_ORGANIZATION,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INDICATOR,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
} from './stixDomainObject';
import { isStixCyberObservable } from './stixCyberObservable';

export const RELATION_DELIVERS = 'delivers';
export const RELATION_TARGETS = 'targets';
export const RELATION_USES = 'uses';
export const RELATION_ATTRIBUTED_TO = 'attributed-to';
export const RELATION_COMPROMISES = 'compromises';
export const RELATION_ORIGINATES_FROM = 'originates-from';
export const RELATION_INVESTIGATES = 'investigates';
export const RELATION_MITIGATES = 'mitigates';
export const RELATION_LOCATED_AT = 'located-at';
export const RELATION_INDICATES = 'indicates';
export const RELATION_BASED_ON = 'based-on';
export const RELATION_COMMUNICATES_WITH = 'communicates-with';
export const RELATION_CONSISTS_OF = 'consists-of';
export const RELATION_CONTROLS = 'controls';
export const RELATION_HAS = 'has';
export const RELATION_HOSTS = 'hosts';
export const RELATION_OWNS = 'owns';
export const RELATION_AUTHORED_BY = 'authored-by';
export const RELATION_BEACONS_TO = 'beacons-to';
export const RELATION_EXFILTRATE_TO = 'exfiltrate-to';
export const RELATION_DOWNLOADS = 'downloads';
export const RELATION_DROPS = 'drops';
export const RELATION_EXPLOITS = 'exploits';
export const RELATION_VARIANT_OF = 'variant-of';
export const RELATION_CHARACTERIZES = 'characterizes';
export const RELATION_ANALYSIS_OF = 'analysis-of';
export const RELATION_STATIC_ANALYSIS_OF = 'static-analysis-of';
export const RELATION_DYNAMIC_ANALYSIS_OF = 'dynamic-analysis-of';
export const RELATION_IMPERSONATES = 'impersonates';
export const RELATION_REMEDIATES = 'remediates';
export const RELATION_RELATED_TO = 'related-to';
export const RELATION_DERIVED_FROM = 'derived-from';
export const RELATION_DUPLICATE_OF = 'duplicate-of';
export const RELATION_PART_OF = 'part-of'; // Extension
export const RELATION_SUBTECHNIQUE_OF = 'subtechnique-of'; // Extension
export const RELATION_REVOKED_BY = 'revoked-by'; // Extension
const STIX_CORE_RELATIONSHIPS = [
  RELATION_DELIVERS,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_BEACONS_TO,
  RELATION_ATTRIBUTED_TO,
  RELATION_EXFILTRATE_TO,
  RELATION_COMPROMISES,
  RELATION_DOWNLOADS,
  RELATION_EXPLOITS,
  RELATION_CHARACTERIZES,
  RELATION_ANALYSIS_OF,
  RELATION_STATIC_ANALYSIS_OF,
  RELATION_DYNAMIC_ANALYSIS_OF,
  RELATION_DERIVED_FROM,
  RELATION_DUPLICATE_OF,
  RELATION_ORIGINATES_FROM,
  RELATION_INVESTIGATES,
  RELATION_LOCATED_AT,
  RELATION_BASED_ON,
  RELATION_HOSTS,
  RELATION_OWNS,
  RELATION_COMMUNICATES_WITH,
  RELATION_MITIGATES,
  RELATION_CONTROLS,
  RELATION_HAS,
  RELATION_CONSISTS_OF,
  RELATION_INDICATES,
  RELATION_VARIANT_OF,
  RELATION_IMPERSONATES,
  RELATION_REMEDIATES,
  RELATION_RELATED_TO,
  RELATION_DROPS,
  RELATION_PART_OF,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_REVOKED_BY,
];
schemaTypes.register(ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_CORE_RELATIONSHIPS);
export const isStixCoreRelationship = (type) =>
  R.includes(type, STIX_CORE_RELATIONSHIPS) || type === ABSTRACT_STIX_CORE_RELATIONSHIP;
// endregion

export const stixCoreRelationshipsAttributes = [
  'internal_id',
  'standard_id',
  'entity_type',
  'created_at',
  'i_created_at_day',
  'i_created_at_month',
  'i_created_at_year',
  'updated_at',
  'x_opencti_stix_ids',
  'spec_version',
  'revoked',
  'confidence',
  'lang',
  'created',
  'modified',
  'relationship_type',
  'description',
  'start_time',
  'i_start_time_day',
  'i_start_time_month',
  'i_start_time_year',
  'stop_time',
  'i_stop_time_day',
  'i_stop_time_month',
  'i_stop_time_year',
];
R.map(
  (stixCoreRelationshipType) =>
    schemaTypes.registerAttributes(stixCoreRelationshipType, stixCoreRelationshipsAttributes),
  STIX_CORE_RELATIONSHIPS
);

export const stixCoreRelationshipsMapping = {
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_SUBTECHNIQUE_OF],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_DELIVERS, RELATION_USES],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_ATTACK_PATTERN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_ATTRIBUTED_TO],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_COMPROMISES, RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_ORIGINATES_FROM, RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_TARGETS],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_MALWARE}`]: [RELATION_USES],
  [`${ENTITY_TYPE_CAMPAIGN}_${ENTITY_TYPE_TOOL}`]: [RELATION_USES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_INDICATOR}`]: [RELATION_INVESTIGATES, RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_MALWARE}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_TOOL}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_COURSE_OF_ACTION}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_MITIGATES],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_SECTOR}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_IDENTITY_SECTOR}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_ORGANIZATION}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_IDENTITY_INDIVIDUAL}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_IDENTITY_ORGANIZATION}`]: [RELATION_PART_OF],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_REGION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_COUNTRY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_CITY}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_IDENTITY_INDIVIDUAL}_${ENTITY_TYPE_LOCATION_POSITION}`]: [RELATION_LOCATED_AT],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_ATTACK_PATTERN}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_CAMPAIGN}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INFRASTRUCTURE}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_INTRUSION_SET}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_MALWARE}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_THREAT_ACTOR}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_TOOL}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_VULNERABILITY}`]: [RELATION_INDICATES],
  [`${ENTITY_TYPE_INDICATOR}_${ENTITY_TYPE_CONTAINER_OBSERVED_DATA}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`]: [RELATION_BASED_ON],
  [`${ENTITY_TYPE_INDICATOR}_${RELATION_USES}`]: [RELATION_INDICATES],
  Infrastructure_Infrastructure: ['communicates-with', 'consists-of', 'controls', 'uses'],
  'Infrastructure_IPv4-Addr': ['communicates-with'],
  'Infrastructure_IPv6-Addr': ['communicates-with'],
  'Infrastructure_Domain-Name': ['communicates-with'],
  Infrastructure_Url: ['communicates-with'],
  'Infrastructure_Observed-Data': ['consists-of'],
  'Infrastructure_Stix-Cyber-Observable': ['consists-of', 'based-on'],
  Infrastructure_Malware: ['controls', 'delivers', 'hosts'],
  Infrastructure_Vulnerability: ['has'],
  Infrastructure_Tool: ['hosts'],
  Infrastructure_Region: ['located-at'],
  Infrastructure_Country: ['located-at'],
  Infrastructure_City: ['located-at'],
  Infrastructure_Position: ['located-at'],
  'Intrusion-Set_Threat-Actor': ['attributed-to', 'targets'],
  'Intrusion-Set_Infrastructure': ['compromises', 'hosts', 'own', 'uses'],
  'Intrusion-Set_Region': ['originates-from', 'targets'],
  'Intrusion-Set_Country': ['originates-from', 'targets'],
  'Intrusion-Set_City': ['originates-from', 'targets'],
  'Intrusion-Set_Position': ['originates-from', 'targets'],
  'Intrusion-Set_Sector': ['targets'],
  'Intrusion-Set_Organization': ['targets'],
  'Intrusion-Set_Individual': ['targets'],
  'Intrusion-Set_Vulnerability': ['targets'],
  'Intrusion-Set_Attack-Pattern': ['uses'],
  'Intrusion-Set_Malware': ['uses'],
  'Intrusion-Set_Tool': ['uses'],
  'Malware_attack-pattern': ['uses'],
  'Malware_Threat-Actor': ['authored-by'],
  'Malware_Intrusion-Set': ['authored-by'],
  Malware_Infrastructure: ['beacons-to', 'exfiltrate-to', 'targets', 'uses'],
  'Malware_IPv4-Addr': ['communicates-with'],
  'Malware_IPv6-Addr': ['communicates-with'],
  'Malware_Domain-Name': ['communicates-with'],
  Malware_Url: ['communicates-with'],
  Malware_Malware: ['controls', 'downloads', 'drops', 'uses', 'variant-of'],
  Malware_Tool: ['downloads', 'drops', 'uses'],
  Malware_StixFile: ['downloads', 'drops'],
  Malware_Vulnerability: ['exploits', 'targets'],
  Malware_Region: ['originates-from', 'targets'],
  Malware_Country: ['originates-from', 'targets'],
  Malware_City: ['originates-from', 'targets'],
  Malware_Position: ['originates-from', 'targets'],
  Malware_Sector: ['targets'],
  Malware_Organization: ['targets'],
  Malware_Individual: ['targets'],
  'Malware_Attack-Pattern': ['uses'],
  'Threat-Actor_Organization': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Individual': ['attributed-to', 'impersonates', 'targets'],
  'Threat-Actor_Sector': ['targets'],
  'Threat-Actor_Infrastructure': ['compromises', 'hosts', 'owns', 'uses'],
  'Threat-Actor_Region': ['located-at', 'targets'],
  'Threat-Actor_Country': ['located-at', 'targets'],
  'Threat-Actor_City': ['located-at', 'targets'],
  'Threat-Actor_Position': ['located-at', 'targets'],
  'Threat-Actor_Attack-Pattern': ['uses'],
  'Threat-Actor_Malware': ['uses'],
  'Threat-Actor_Tool': ['uses'],
  'Tool_Attack-Pattern': ['uses', 'drops', 'delivers'],
  Tool_Malware: ['uses', 'drops', 'delivers'],
  Tool_Vulnerability: ['has', 'targets'],
  Tool_Sector: ['targets'],
  Tool_Organization: ['targets'],
  Tool_Individual: ['targets'],
  Tool_Region: ['targets'],
  Tool_Country: ['targets'],
  Tool_City: ['targets'],
  Tool_Position: ['targets'],
  'X-OpenCTI-Incident_Intrusion-Set': ['attributed-to'],
  'X-OpenCTI-Incident_Threat-Actor': ['attributed-to'],
  'X-OpenCTI-Incident_Campaign': ['attributed-to'],
  'X-OpenCTI-Incident_Infrastructure': ['compromises', 'uses'],
  'X-OpenCTI-Incident_Region': ['originates-from', 'targets'],
  'X-OpenCTI-Incident_Country': ['originates-from', 'targets'],
  'X-OpenCTI-Incident_City': ['originates-from', 'targets'],
  'X-OpenCTI-Incident_Position': ['originates-from', 'targets'],
  'X-OpenCTI-Incident_Sector': ['targets'],
  'X-OpenCTI-Incident_Organization': ['targets'],
  'X-OpenCTI-Incident_Individual': ['targets'],
  'X-OpenCTI-Incident_Vulnerability': ['targets'],
  'X-OpenCTI-Incident_Attack-Pattern': ['uses'],
  'X-OpenCTI-Incident_Malware': ['uses'],
  'X-OpenCTI-Incident_Tool': ['uses'],
  Region_Region: ['located-at'],
  Country_Region: ['located-at'],
  City_Country: ['located-at'],
  Position_City: ['located-at'],
  'IPv4-Addr_Region': ['located-at'],
  'IPv4-Addr_Country': ['located-at'],
  'IPv4-Addr_City': ['located-at'],
  'IPv4-Addr_Position': ['located-at'],
  'IPv6-Addr_Region': ['located-at'],
  'IPv6-Addr_Country': ['located-at'],
  'IPv6-Addr_City': ['located-at'],
  'IPv6-Addr_Position': ['located-at'],
  targets_Region: ['located-at'],
  targets_Country: ['located-at'],
  targets_City: ['located-at'],
  targets_Position: ['located-at'],
};

export const checkStixCoreRelationshipMapping = (fromType, toType, relationshipType) => {
  if (relationshipType === RELATION_RELATED_TO || relationshipType === RELATION_REVOKED_BY) {
    return true;
  }
  if (relationshipType === RELATION_BASED_ON && isStixCyberObservable(toType)) {
    return !!R.includes(
      relationshipType,
      stixCoreRelationshipsMapping[`${fromType}_${ABSTRACT_STIX_CYBER_OBSERVABLE}`] || []
    );
  }
  return !!R.includes(relationshipType, stixCoreRelationshipsMapping[`${fromType}_${toType}`] || []);
};
