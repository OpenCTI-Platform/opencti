import {
  aliases,
  created,
  createdAt,
  creators,
  entityLocationType,
  entityType,
  files,
  iAliasedIds,
  identityClass,
  internalId,
  lang,
  modified,
  revoked,
  standardId,
  updatedAt,
  xOpenctiAliases,
  xOpenctiStixIds
} from '../schema/attribute-definition';
import { xOpenctiLinkedTo } from '../schema/stixRefRelationship';

export const INTERNAL_ATTRIBUTES = [
  // ID
  internalId.name,
  standardId.name,
  xOpenctiStixIds.name,
  'external_id',
  iAliasedIds.name,
  // Auditing
  createdAt.name,
  updatedAt.name,
  modified.name,
  // Technical
  created.name,
  entityType.name,
  'relationship_type',
  identityClass.name,
  creators.name,
  files.name,
  lang.name,
  revoked.name,
  aliases.name,
  entityLocationType.name,
  'i_inference_weight',
  'content_mapping',
  'caseTemplate',
  'default_dashboard',
  'default_hidden_types',
  'grantable_groups',
  'authorized_members',
  'authorized_authorities',
  // X - Mitre
  'x_mitre_permissions_required',
  'x_mitre_detection',
  'x_mitre_id',
  'x_opencti_graph_data',
  // X - OpenCTI
  xOpenctiAliases.name,
  'x_opencti_workflow_id',
  'x_opencti_detection',
  'x_opencti_threat_hunting',
  'x_opencti_log_sources',
  'x_opencti_firstname',
  'x_opencti_lastname',
  'x_opencti_score',
  'x_opencti_base_score',
  'x_opencti_base_severity',
  'x_opencti_attack_vector',
  'x_opencti_integrity_impact',
  'x_opencti_availability_impact',
  'x_opencti_confidentiality_impact',
  'x_opencti_additional_names',
];

export const INTERNAL_REFS = [
  xOpenctiLinkedTo.inputName,
  'objectOrganization'
];
