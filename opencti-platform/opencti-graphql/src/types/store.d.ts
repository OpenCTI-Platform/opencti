import type { SortResults } from '@elastic/elasticsearch/lib/api/types';
import {
  INPUT_BCC,
  INPUT_BELONGS_TO,
  INPUT_BODY_MULTIPART,
  INPUT_BODY_RAW,
  INPUT_CC,
  INPUT_CHILD,
  INPUT_CONTAINS,
  INPUT_CONTENT,
  INPUT_CREATOR_USER,
  INPUT_DST,
  INPUT_DST_PAYLOAD,
  INPUT_EMAIL_FROM,
  INPUT_EMAIL_TO,
  INPUT_ENCAPSULATED_BY,
  INPUT_ENCAPSULATES,
  INPUT_IMAGE,
  INPUT_OPENED_CONNECTION,
  INPUT_OPERATING_SYSTEM,
  INPUT_PARENT,
  INPUT_PARENT_DIRECTORY,
  INPUT_RAW_EMAIL,
  INPUT_RESOLVES_TO,
  INPUT_SAMPLE,
  INPUT_SENDER,
  INPUT_SERVICE_DLL,
  INPUT_SRC,
  INPUT_SRC_PAYLOAD,
  INPUT_VALUES,
  RELATION_CREATED_BY,
  RELATION_EXTERNAL_REFERENCE,
  RELATION_GRANTED_TO,
  RELATION_OBJECT,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING,
  RELATION_OBJECT_PARTICIPANT,
} from '../schema/stixRefRelationship';
import {
  INPUT_ASSIGNEE,
  INPUT_CREATED_BY,
  INPUT_DOMAIN_FROM,
  INPUT_DOMAIN_TO,
  INPUT_EXTERNAL_REFS,
  INPUT_GRANTED_REFS,
  INPUT_IN_PIR,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  INPUT_PARTICIPANT,
} from '../schema/general';
import type { StixId } from './stix-2-1-common';
import { type EditOperation, type PageInfo, StatusScope } from '../generated/graphql';
import type { windows_integrity_level_enum, ssh_key_type_enum, windows_service_start_type_enum, windows_service_status_enum, windows_service_type_enum } from './stix-2-1-sco';
import { RELATION_MEMBER_OF, RELATION_IN_PIR } from '../schema/internalRelationship';
import { AuthorizedMember } from '../utils/access';
import type { Metric } from '../modules/metrics/metrics';
import type { PirInformation } from '../modules/pir/pir-types';

interface Representative {
  main: string;
  secondary: string;
}

interface InternalEditInput {
  key: string;
  operation?: EditOperation | null;
  value: (string | Record<string, any> | null)[];
  previous?: any[];
}

interface NumberResult {
  count: number;
  total: number;
}

interface StoreFile {
  id: string;
  name: string;
  version?: string;
  mime_type?: string;
  description?: string;
  order?: number;
  inCarousel?: boolean;
  file_markings?: string[];
  [INPUT_MARKINGS]?: Array<StoreMarkingDefinition>;
  data?: string;
}

interface StoreFileWithRefs extends StoreFile {
  [INPUT_MARKINGS]?: Array<StoreMarkingDefinition>;
}

interface DraftChange {
  draft_operation: string;
  draft_updates_patch?: string;
}

interface BasicStoreIdentifier {
  id: string;
  internal_id: string;
  standard_id?: StixId;
  entity_type: string;
  x_opencti_stix_ids?: Array<StixId>;
}

interface BasicStoreBase extends BasicStoreIdentifier {
  _id: string;
  _index: string;
  standard_id: StixId;
  entity_type: string;
  base_type: 'ENTITY' | 'RELATION';
  parent_types: string[];
  spec_version: string;
  i_attributes?: { name: string; updated_at: string; confidence: number; user_id: string }[];
  created_at: Date;
  updated_at: Date;
  refreshed_at?: Date;
  x_opencti_files?: Array<StoreFile>;
  x_opencti_aliases?: Array<string>;
  i_aliases_ids?: Array<string>;
  x_opencti_stix_ids?: Array<StixId>;
  x_opencti_workflow_id?: string;
  creator_id?: string | string[];
  type?: string;
  draft_ids?: string[];
  draft_change?: DraftChange;
  sort?: SortResults;
  // representative
  representative: Representative;
  restricted_members?: Array<AuthorizedMember>;
  metrics?: Array<Metric>;
  pir_information?: Array<PirInformation>;
}

interface StoreMarkingDefinition extends BasicStoreEntity {
  definition: string;
  definition_type: string;
  x_opencti_order: number;
  x_opencti_color: string;
}

interface StoreLabel extends BasicStoreBase {
  value: string;
  color: string;
}

interface StoreKillChainPhases extends BasicStoreBase {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
}

interface StoreExternalReferences extends BasicStoreBase {
  source_name: string;
  description: string;
  url: string;
  hashes: { [k: string]: string };
  external_id: string;
}

interface StoreWindowsRegistryValueType extends BasicStoreBase {
  name: string;
  data: string;
  data_type: string;
}

interface StoreConnection {
  internal_id: string;
  role: string;
  types: Array<string>;
  name?: string;
}

interface StoreRawRule {

  inferred: any;
  explanation: string[];
}

interface StoreRule {
  rule: string;
  attributes: Array<{ field: string; value: string }>;
  explanation: string[];
}

interface BasicStoreCommon extends BasicStoreBase {
  // Array
  [k: `i_rule_${string}`]: Array<StoreRawRule>;
  // object
  hashes?: { [k: string]: string };
  // inputs
  [RELATION_GRANTED_TO]?: Array<string>;
  [RELATION_OBJECT_MARKING]?: Array<string>;
  [RELATION_OBJECT_LABEL]?: Array<string>;
  [RELATION_CREATED_BY]?: string;
  [RELATION_OBJECT_ASSIGNEE]?: Array<string>;
  [RELATION_OBJECT_PARTICIPANT]?: Array<string>;
  [RELATION_EXTERNAL_REFERENCE]?: Array<string>;
  [RELATION_IN_PIR]?: Array<string>;
}

interface StoreCommon {
  internal_id: string;
  standard_id: StixId;
  entity_type: string;
  parent_types: string[];
  // inputs
  [INPUT_MARKINGS]?: Array<StoreMarkingDefinition>;
  [INPUT_ASSIGNEE]?: Array<BasicStoreObject>;
  [INPUT_PARTICIPANT]?: Array<BasicStoreObject>;
  [INPUT_EXTERNAL_REFS]?: Array<StoreExternalReferences>;
  [INPUT_GRANTED_REFS]?: Array<BasicStoreObject>;
  [INPUT_IN_PIR]?: Array<BasicStoreObject>;
}

interface StoreProxyRelation extends BasicStoreCommon {
  _index: string;
}

interface StoreRawRelation extends StoreProxyRelation {
  lang: string;
  relationship_type: string;
  description: string;
  summary: string;
  // rels
  [RELATION_OBJECT_MARKING]: Array<string>;
  // date
  first_seen: Date;
  last_seen: Date;
  start_time: Date;
  stop_time: Date;
  created: Date;
  modified: Date;
  // custom:
  x_opencti_modified_at: Date;
  // boolean
  revoked: boolean;
  x_opencti_negative: boolean;
  is_inferred: boolean;
  // number
  confidence: number;
  attribute_count: number;
  // Array
  connections: Array<StoreConnection>;
}

interface BasicStoreRelation extends StoreRawRelation {
  fromId: string;
  fromRole: string;
  fromType: string;
  fromName: string;
  toId: string;
  toRole: string;
  toType: string;
  toName: string;
  coverage: Array<{ name: string; score: number }>;
}

interface StoreRelation extends BasicStoreRelation, StoreCommon {
  from: BasicStoreBase | undefined | null;
  to: BasicStoreBase | undefined | null;
  [INPUT_CREATED_BY]: BasicStoreEntity;
  [INPUT_DOMAIN_FROM]: BasicStoreObject;
  [INPUT_DOMAIN_TO]: BasicStoreObject;
  [INPUT_LABELS]: Array<StoreLabel>;
  [INPUT_KILLCHAIN]: Array<StoreKillChainPhases>;
}

interface BasicNodeEdge<T> {
  cursor: string;
  types?: (string | null | undefined)[];
  node: T;
}

interface BasicConnection<T> {
  edges: Array<BasicNodeEdge<T>>;
  pageInfo: PageInfo;
}

interface BasicStoreEntity extends BasicStoreCommon {
  id: string;
  name: string;
  spec_version: string;
  content_type: string;
  content_disposition: string;
  body: string;
  lang: string;
  value: string;
  color: string;
  attribute_abstract: string;
  content: string;
  content_mapping: string;
  pattern: string;
  pattern_type: string;
  pattern_version: string;
  identity_class: string;
  contact_information: string;
  sophistication: string;
  resource_level: string;
  primary_motivation: string;
  region: string;
  country: string;
  city: string;
  street_address: string;
  postal_code: string;
  explanation: string;
  description: string;
  definition: string;
  definition_type: string;
  objective: string;
  tool_version: string;
  context: string;
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree';
  x_mitre_id: string;
  x_mitre_detection: string;
  x_opencti_color: string;
  kill_chain_name: string;
  phase_name: string;
  url: string;
  source_name: string;
  external_id: string;
  lastEventId: string;
  platform_organization: string;
  source: string;
  severity: string;
  incident_type: string;
  // custom
  x_opencti_location_type: string;
  x_opencti_reliability: string;
  x_opencti_organization_type: string;
  // CVSS3
  x_opencti_cvss_vector_string: string;
  x_opencti_cvss_base_severity: string;
  x_opencti_cvss_attack_vector: string;
  x_opencti_cvss_attack_complexity: string;
  x_opencti_cvss_privileges_required: string;
  x_opencti_cvss_user_interaction: string;
  x_opencti_cvss_scope: string;
  x_opencti_cvss_confidentiality_impact: string;
  x_opencti_cvss_integrity_impact: string;
  x_opencti_cvss_availability_impact: string;
  x_opencti_cvss_exploit_code_maturity: string;
  x_opencti_cvss_remediation_level: string;
  x_opencti_cvss_report_confidence: string;
  // CVSS2
  x_opencti_cvss_v2_vector_string: string;
  x_opencti_cvss_v2_access_vector: string;
  x_opencti_cvss_v2_access_complexity: string;
  x_opencti_cvss_v2_authentication: string;
  x_opencti_cvss_v2_confidentiality_impact: string;
  x_opencti_cvss_v2_integrity_impact: string;
  x_opencti_cvss_v2_availability_impact: string;
  x_opencti_cvss_v2_exploitability: string;
  x_opencti_cvss_v2_remediation_level: string;
  x_opencti_cvss_v2_report_confidence: string;
  // CVSS4
  x_opencti_cvss_v4_vector_string: string;
  x_opencti_cvss_v4_base_severity: string;
  x_opencti_cvss_v4_attack_vector: string;
  x_opencti_cvss_v4_attack_complexity: string;
  x_opencti_cvss_v4_attack_requirements: string;
  x_opencti_cvss_v4_privileges_required: string;
  x_opencti_cvss_v4_user_interaction: string;
  x_opencti_cvss_v4_confidentiality_impact_v: string;
  x_opencti_cvss_v4_confidentiality_impact_s: string;
  x_opencti_cvss_v4_integrity_impact_v: string;
  x_opencti_cvss_v4_integrity_impact_s: string;
  x_opencti_cvss_v4_availability_impact_v: string;
  x_opencti_cvss_v4_availability_impact_s: string;
  x_opencti_cvss_v4_exploit_maturity: string;
  // Others
  x_opencti_cwe: string;
  x_opencti_main_observable_type: string;
  x_opencti_lastname: string;
  x_opencti_firstname: string;
  x_opencti_inferences: Array<StoreRule> | undefined;
  // internal
  i_relation: BasicStoreRelation; // internal related relation for refs
  // rels
  [RELATION_CREATED_BY]: string;
  [RELATION_OBJECT]: Array<string>;
  // array
  collection_layers: Array<string>;
  received_lines: Array<string>;
  parent_types: Array<string>;
  report_types: Array<string>;
  malware_types: Array<string>;
  aliases: Array<string>;
  authors: Array<string>;
  indicator_types: Array<string>;
  roles: Array<string>;
  sectors: Array<string>;
  goals: Array<string>;
  secondary_motivations: Array<string>;
  personal_motivations: Array<string>;
  infrastructure_types: Array<string>;
  threat_actor_types: Array<string>;
  tool_types: Array<string>;
  architecture_execution_envs: Array<string>;
  implementation_languages: Array<string>;
  capabilities: Array<string>;
  note_types: Array<string>;
  // custom
  x_mitre_permissions_required: Array<string>;
  x_mitre_platforms: Array<string>;
  // dates
  created: Date;
  modified: Date;
  published: Date;
  first_seen: Date;
  last_seen: Date;
  valid_from: Date;
  valid_until: Date;
  first_observed: Date;
  last_observed: Date;
  // custom
  x_opencti_first_seen_active: Date;
  x_opencti_modified_at: Date;
  // boolean
  revoked: boolean;
  is_family: boolean;
  is_inferred: boolean;
  // custom
  x_opencti_detection: boolean;
  x_opencti_cisa_kev: boolean;
  // number
  number_observed: number;
  confidence: number;
  latitude: string;
  longitude: string;
  precision: number;
  // custom
  usages: number;
  likelihood: number;
  x_opencti_order: number;
  x_opencti_score: number;
  x_opencti_epss_score: number;
  x_opencti_epss_percentile: number;
  // CVSS3
  x_opencti_cvss_base_score: number;
  x_opencti_cvss_temporal_score: number;
  // CVSS2
  x_opencti_cvss_v2_base_score: number;
  x_opencti_cvss_v2_temporal_score: number;
  // CVSS4
  x_opencti_cvss_v4_base_score: number;
  // PIR
  pir_information?: Array<PirInformation>;
}

interface StoreEntity extends BasicStoreEntity, StoreCommon {
  [INPUT_CREATED_BY]: BasicStoreEntity;
  [INPUT_SAMPLE]: Array<StoreCyberObservable>;
  [INPUT_OPERATING_SYSTEM]: Array<StoreCyberObservable>;
  [INPUT_RAW_EMAIL]: Array<BasicStoreEntity>;
  [INPUT_OBJECTS]: Array<BasicStoreEntity>;
  [INPUT_LABELS]: Array<StoreLabel>;
  [INPUT_KILLCHAIN]: Array<StoreKillChainPhases>;
}

interface StoreEntityReport extends StoreCommon {
  name: string;
  published: Date;
  [INPUT_OBJECTS]: Array<StoreEntity>;
}

interface BasicStoreEntityFeed extends BasicStoreEntity {
  id: string;
  name: string;
  filters: string;
  separator: string;
  entity_type: 'Feed';
  rolling_time: number;
  include_header: boolean;
  feed_public: boolean;
  feed_types: Array<string>;
  feed_date_attribute: string;
  feed_attributes: Array<{
    attribute: string;
    mappings: [{
      type: string;
      attribute: string;
    }];
  }>;
  restricted_members: Array<AuthorizedMember>;
}

interface BasicStoreCyberObservable extends BasicStoreCommon {
  // string
  attribute_key: string;
  content_type: string;
  message_id: string;
  subject: string;
  body: string;
  value: string;
  display_name: string;
  group_name: string;
  mime_type: string;
  payload_bin: string;
  url: string;
  encryption_algorithm: string;
  decryption_key: string;
  x_opencti_description: string;
  path: string;
  path_enc: string;
  rir: string;
  name_enc: string;
  magic_number_hex: string;
  content_disposition: string;
  cwd: string;
  command_line: string;
  cpe: string;
  swid: string;
  vendor: string;
  version: string;
  user_id: string;
  credential: string;
  account_login: string;
  account_type: string;
  serial_number: string;
  signature_algorithm: string;
  issuer: string;
  subject_public_key_algorithm: string;
  subject_public_key_modulus: string;
  basic_constraints: string;
  name_constraints: string;
  policy_constraints: string;
  key_usage: string;
  extended_key_usage: string;
  subject_key_identifier: string;
  authority_key_identifier: string;
  subject_alternative_name: string;
  issuer_alternative_name: string;
  subject_directory_attributes: string;
  crl_distribution_points: string;
  inhibit_any_policy: string;
  certificate_policies: string;
  policy_mappings: string;
  name: string;
  data: string;
  data_type: string;
  iban: string;
  bic: string;
  holder_name: string;
  card_number: string;
  account_number: string;
  title: string;
  content: string;
  media_category: string;
  service_name: string;
  priority: string;
  owner_sid: string;
  window_title: string;
  persona_name: string;
  persona_type: string;
  public_key: string;
  fingerprint_sha256: string;
  fingerprint_md5: string;
  key_length: number;
  comment: string;
  // custom
  x_opencti_product: string;
  // date
  attribute_date: Date;
  ctime: Date;
  mtime: Date;
  atime: Date;
  start: Date;
  end: Date;
  created_time: Date;
  account_created: Date;
  account_expires: Date;
  credential_last_changed: Date;
  account_first_login: Date;
  account_last_login: Date;
  modified_time: Date;
  validity_not_before: Date;
  validity_not_after: Date;
  private_key_usage_period_not_before: Date;
  private_key_usage_period_not_after: Date;
  expiration_date: Date;
  publication_date: Date;
  created: Date;
  // custom
  x_opencti_modified_at: Date;
  // boolean
  defanged: boolean;
  is_multipart: boolean;
  is_active: boolean;
  is_hidden: boolean;
  is_service_account: boolean;
  is_privileged: boolean;
  can_escalate_privs: boolean;
  is_disabled: boolean;
  is_self_signed: boolean;
  aslr_enabled: boolean;
  dep_enabled: boolean;
  // Array
  x_opencti_additional_names: Array<string>;
  received_lines: Array<string>;
  protocols: Array<string>;
  languages: Array<string>;
  descriptions: Array<string>;
  // number
  x_opencti_score: number;
  number: number;
  size: number;
  src_port: number;
  dst_port: number;
  src_byte_count: number;
  dst_byte_count: number;
  src_packets: number;
  dst_packets: number;
  pid: number;
  number_of_subkeys: number;
  subject_public_key_exponent: number;
  cvv: number;
  // object
  ipfix: object;
  environment_variables: object;
  startup_info: object;
  // enum
  start_type: windows_service_start_type_enum;
  service_type: windows_service_type_enum;
  service_status: windows_service_status_enum;
  integrity_level: windows_integrity_level_enum;
  key_type: ssh_key_type_enum;
}

interface StoreCyberObservable extends BasicStoreCyberObservable, StoreCommon {
  [INPUT_CREATED_BY]: BasicStoreEntity;
  [INPUT_CONTAINS]: Array<BasicStoreObject>;
  [INPUT_BODY_MULTIPART]: Array<BasicStoreEntity>;
  [INPUT_PARENT_DIRECTORY]: BasicStoreObject;
  [INPUT_BODY_RAW]: BasicStoreObject;
  [INPUT_SRC]: BasicStoreObject;
  [INPUT_DST]: BasicStoreObject;
  [INPUT_SRC_PAYLOAD]: BasicStoreObject;
  [INPUT_DST_PAYLOAD]: BasicStoreObject;
  [INPUT_ENCAPSULATED_BY]: BasicStoreObject;
  [INPUT_CREATOR_USER]: BasicStoreObject;
  [INPUT_IMAGE]: BasicStoreObject;
  [INPUT_PARENT]: BasicStoreObject;
  [INPUT_CHILD]: Array<BasicStoreObject>;
  [INPUT_ENCAPSULATES]: Array<BasicStoreObject>;
  [INPUT_OPENED_CONNECTION]: Array<BasicStoreObject>;
  [INPUT_SERVICE_DLL]: Array<BasicStoreObject>;
  [INPUT_CC]: Array<BasicStoreObject>;
  [INPUT_BCC]: Array<BasicStoreObject>;
  [INPUT_EMAIL_TO]: Array<BasicStoreObject>;
  [INPUT_RESOLVES_TO]: Array<BasicStoreObject>;
  [INPUT_BELONGS_TO]: Array<BasicStoreObject>;
  [INPUT_SENDER]: BasicStoreObject;
  [INPUT_RAW_EMAIL]: BasicStoreObject;
  [INPUT_EMAIL_FROM]: BasicStoreObject;
  [INPUT_CONTENT]: BasicStoreObject;
  [INPUT_VALUES]: Array<StoreWindowsRegistryValueType>;
  [INPUT_LABELS]: Array<StoreLabel>;
  [INPUT_EXTERNAL_REFS]: Array<StoreExternalReferences>;
}

interface BasicRuleEntity extends BasicStoreEntity {
  active: boolean;
}

interface BasicManagerEntity extends BasicStoreEntity {
  errors: Array<{
    error: string;
    source: string;
    timestamp: Date;
  }>;
  lastEventId: string;
}

interface BasicWorkflowStatus extends BasicStoreEntity {
  order: number;
  template_id: string;
  type: string;
  scope: StatusScope;
}

interface BasicTaskEntity extends BasicStoreEntity {
  completed: boolean;
  created_at: Date;
}

interface BasicWorkflowTemplateEntity extends BasicStoreEntity {
  name: string;
  color: string;
}

interface BasicStreamEntity extends BasicStoreEntity {
  filters: string;
}

interface BasicTriggerEntity extends BasicStoreEntity {
  filters: string;
}

interface BasicWorkflowStatusEntity extends BasicStoreEntity {
  template_id: string;
  type: string;
  order: number;
  disabled: boolean;
}

interface BasicIdentityEntity extends BasicStoreEntity {
  name: string;
  description: string;
  roles: string[];
  identity_class: string;
  contact_information: string;
  x_opencti_aliases?: string[];
}

interface StoreEntityIdentity extends StoreEntity, BasicIdentityEntity {}

interface BasicGroupEntity extends BasicStoreEntity {
  [RELATION_MEMBER_OF]: string[];
  auto_integration_assignation: string[];
}

interface BasicOrganizationEntity extends BasicStoreEntity {
  [RELATION_PARTICIPATE_TO]: string[];
}

export interface BasicStoreEntityMarkingDefinition extends BasicStoreBase {
  definition: string;
  definition_type: string;
  x_opencti_order: number;
  revoked: boolean;
  is_inferred: boolean;
}

export interface BasicStoreEntityIdentity extends BasicStoreBase {
  name: string;
  revoked: boolean;
  description: string;
  identity_class: string;
  is_inferred: boolean;
}

type BasicStoreObject = BasicStoreEntity | BasicStoreCyberObservable | BasicStoreRelation;
type StoreObject = StoreEntity | StoreCyberObservable | StoreRelation;
