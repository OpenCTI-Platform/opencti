import * as R from 'ramda';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey, schemaTypes } from './general';
import {
  RELATION_CREATED_BY, RELATION_EXTERNAL_REFERENCE,
  RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from './stixMetaRelationship';

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
];

schemaTypes.register(ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_CORE_RELATIONSHIPS);
export const isStixCoreRelationship = (type: string): boolean => {
  return R.includes(type, STIX_CORE_RELATIONSHIPS) || type === ABSTRACT_STIX_CORE_RELATIONSHIP;
};

export const stixCoreRelationshipOptions = {
  StixCoreRelationshipsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    objectContains: buildRefRelationKey(RELATION_OBJECT),
    containedBy: buildRefRelationKey(RELATION_OBJECT),
    hasExternalReference: buildRefRelationKey(RELATION_EXTERNAL_REFERENCE),
  },
};
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
  'i_inference_weight',
  'x_opencti_workflow_id',
];
schemaTypes.registerAttributes(ABSTRACT_STIX_CORE_RELATIONSHIP, stixCoreRelationshipsAttributes);
R.map((type) => schemaTypes.registerAttributes(type, stixCoreRelationshipsAttributes), STIX_CORE_RELATIONSHIPS);
