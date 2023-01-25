import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey } from './general';
import {
  RELATION_CREATED_BY,
  RELATION_KILL_CHAIN_PHASE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from './stixMetaRelationship';
import {
  AttributeDefinition,
  confidence, created,
  createdAt,
  entityType,
  IcreatedAtDay,
  IcreatedAtMonth,
  IcreatedAtYear,
  internalId, lang, modified, relationshipType, revoked, specVersion,
  standardId, updatedAt, xOpenctiStixIds
} from './attribute-definition';
import { schemaAttributesDefinition } from './schema-attributes';

// region Standard STIX core
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
export const RELATION_EXFILTRATES_TO = 'exfiltrates-to';
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
export const RELATION_BELONGS_TO = 'belongs-to';
export const RELATION_RESOLVES_TO = 'resolves-to';
// endregion

// region Extended relationships
export const RELATION_PART_OF = 'part-of'; // Extension (OpenCTI)
export const RELATION_COOPERATES_WITH = 'cooperates-with'; // Extension (OpenCTI)
export const RELATION_PARTICIPATES_IN = 'participates-in'; // Extension (OpenCTI)
export const RELATION_PUBLISHES = 'publishes'; // Extension (OpenCTI)
export const RELATION_AMPLIFIES = 'amplifies'; // Extension (OpenCTI)
export const RELATION_SUBNARRATIVE_OF = 'subnarrative-of'; // Extension (OpenCTI)
export const RELATION_SUBTECHNIQUE_OF = 'subtechnique-of'; // Extension (MITRE)
export const RELATION_REVOKED_BY = 'revoked-by'; // Extension (MITRE)
export const RELATION_DETECTS = 'detects'; // Extension (MITRE)
// endregion

export const STIX_CORE_RELATIONSHIPS = [
  RELATION_DELIVERS,
  RELATION_TARGETS,
  RELATION_USES,
  RELATION_BEACONS_TO,
  RELATION_ATTRIBUTED_TO,
  RELATION_EXFILTRATES_TO,
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
  RELATION_AUTHORED_BY,
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
  RELATION_COOPERATES_WITH,
  RELATION_PARTICIPATES_IN,
  RELATION_SUBTECHNIQUE_OF,
  RELATION_REVOKED_BY,
  RELATION_BELONGS_TO,
  RELATION_RESOLVES_TO,
  RELATION_DETECTS,
  RELATION_PUBLISHES,
  RELATION_AMPLIFIES,
  RELATION_SUBNARRATIVE_OF,
];

schemaAttributesDefinition.register(ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_CORE_RELATIONSHIPS);
export const isStixCoreRelationship = (type: string): boolean => schemaAttributesDefinition.get(ABSTRACT_STIX_CORE_RELATIONSHIP).includes(type)
 || type === ABSTRACT_STIX_CORE_RELATIONSHIP;

export const stixCoreRelationshipOptions = {
  StixCoreRelationshipsFilter: {
    creator: 'creator_id',
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    killChainPhase: buildRefRelationKey(RELATION_KILL_CHAIN_PHASE),
  },
  StixCoreRelationshipsOrdering: {}
};
export const stixCoreRelationshipsAttributes: Array<AttributeDefinition> = [
  internalId,
  standardId,
  entityType,
  createdAt,
  IcreatedAtDay,
  IcreatedAtMonth,
  IcreatedAtYear, //  Not in add input
  updatedAt,
  xOpenctiStixIds,
  specVersion,
  revoked,
  confidence,
  lang,
  created,
  modified,

  relationshipType,
  { name: 'description', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'start_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_start_time_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_start_time_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_start_time_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'stop_time', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_stop_time_day', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_stop_time_month', type: 'date', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_stop_time_year', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'i_inference_weight', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
  { name: 'x_opencti_workflow_id', type: 'string', mandatoryType: 'no', multiple: false, upsert: false },
];
schemaAttributesDefinition.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
STIX_CORE_RELATIONSHIPS.map((type) => schemaAttributesDefinition.registerAttributes(type, stixCoreRelationshipsAttributes));
