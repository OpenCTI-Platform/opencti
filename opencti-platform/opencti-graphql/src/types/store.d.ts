import { v4, v5 } from 'uuid';
import { MappingRuntimeFieldType, SortResults } from '@elastic/elasticsearch/api/types';
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
  INPUT_ENCAPSULATED_BY,
  INPUT_ENCAPSULATES,
  INPUT_FROM,
  INPUT_IMAGE,
  INPUT_OPENED_CONNECTION,
  INPUT_PARENT,
  INPUT_PARENT_DIRECTORY,
  INPUT_RAW_EMAIL,
  INPUT_RESOLVES_TO,
  INPUT_SENDER,
  INPUT_SRC,
  INPUT_SRC_PAYLOAD,
  INPUT_TO,
  INPUT_VALUES
} from '../schema/stixCyberObservableRelationship';
import {
  INPUT_CREATED_BY,
  INPUT_DOMAIN_FROM,
  INPUT_DOMAIN_TO,
  INPUT_EXTERNAL_REFS,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS
} from '../schema/general';
import type { AuthUser } from './user';
import type { StixPatch, StixContext, StixObject } from './stix-common';
import { RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';

type StorePrimitives = string | number | boolean | Date;

interface StorePatch {
  key: string;
  value: Array<StorePrimitives | StixObject>;
}

interface StoreInput {
  key: string;
  value: Array<StorePrimitives | BasicStoreObject>;
}

interface StoreInputOperation extends StoreInput {
  operation: 'add' | 'replace' | 'remove' | 'change';
  previous: Array<StorePrimitives | BasicStoreObject>;
}

interface StoreBase {
  _index: string;
  name: string;
  standard_id: `${string}--${v4 | v5}`;
  internal_id: string;
  entity_type: string;
  base_type: string;
  x_opencti_stix_ids: array<string>;
  x_opencti_inferences: Array<StoreRule> | undefined;
  x_opencti_patch: StixPatch | undefined;
  x_opencti_context: StixContext ;
  created_at: Date;
  updated_at: Date;
}

interface StorePartial {
  [k: string]: unknown;
}

interface StoreMarkingDefinition extends StoreBase {
  definition: string;
  definition_type: string;
  x_opencti_order: number;
  x_opencti_color: string;
}

interface StoreLabel extends StoreBase {
  value: string;
}

interface StoreKillChainPhases extends StoreBase {
  kill_chain_name: string;
  phase_name: string;
  x_opencti_order: number;
}

interface StoreExternalReferences extends StoreBase {
  source_name: string;
  description: string;
  url: string;
  hashes: { [k: string]: string };
  external_id: string;
}

interface StoreWindowsRegistryValueType extends StoreBase {
  name: string;
  data: string;
  data_type: string;
}

interface StoreConnection {
  internal_id: string;
  role: string;
  types: array<string>;
}

interface StoreRawRule {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  inferred: any;
  explanation: array<string>;
}

interface StoreRule {
  rule: string;
  attributes: Array<{ field: string, value: string }>;
  explanation: array<string>;
}

interface StoreRuntimeAttribute {
  [k: string]: {
    field: string;
    type: MappingRuntimeFieldType;
    getSource: () => Promise<string>;
    getParams: (user: AuthUser) => Promise<Record<string, unknown> | undefined>;
  },
}

interface BasicStoreCommon extends StoreBase {
  // array
  [k: `i_rule_${string}`]: Array<StoreRawRule>;
  // [k: `rel_${string}`]: Array<string>;
  // object
  hashes: { [k: string]: string };
  sort?: SortResults;
  // inputs
  // [INPUT_MARKINGS]?: Array<StoreMarkingDefinition>;
  [RELATION_OBJECT_MARKING]: Array<string>;
  // [INPUT_EXTERNAL_REFS]?: Array<StoreExternalReferences>;
  [RELATION_EXTERNAL_REFERENCE]: Array<string>;
}

interface StoreCommon {
  // inputs
  [INPUT_MARKINGS]?: Array<StoreMarkingDefinition>;
  [INPUT_EXTERNAL_REFS]?: Array<StoreExternalReferences>;
}

interface StoreRawRelation extends BasicStoreCommon {
  lang: string;
  relationship_type: string;
  description: string;
  summary: string;
  // inputs
  [RELATION_OBJECT_MARKING]: Array<string>;
  // date
  first_seen: Date;
  last_seen: Date;
  start_time: Date;
  stop_time: Date;
  created: Date;
  // boolean
  revoked: boolean;
  negative: boolean;
  // number
  confidence: number;
  attribute_count: number;
  // array
  connections: Array<StoreConnection>;
}
interface BasicStoreRelation extends StoreRawRelation {
  from: BasicStoreObject | undefined;
  fromId: string;
  fromRole: string;
  fromType: array<string>;
  to: BasicStoreObject | undefined;
  toId: string;
  toRole: string;
  toType: array<string>;
}
interface StoreRelation extends BasicStoreRelation, StoreCommon {
  [INPUT_CREATED_BY]: StoreBasicEntity;
  [INPUT_DOMAIN_FROM]: StoreBasicEntity;
  [INPUT_DOMAIN_TO]: StoreBasicEntity;
  [INPUT_LABELS]: Array<StoreLabel>;
}

interface BasicStoreEntity extends BasicStoreCommon {
  lang: string;
  value: string;
  color: string;
  attribute_abstract: string;
  content: string;
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
  administrative_area: string;
  city: string;
  street_address: string;
  postal_code: string;
  explanation: string;
  description: string;
  definition: string;
  definition_type: string;
  objective: string;
  tool_version: string;
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree';
  x_mitre_id: string;
  x_opencti_color: string;
  kill_chain_name: string;
  phase_name: string;
  url: string;
  source_name: string;
  external_id: string;
  // rels
  [RELATION_OBJECT_MARKING]: Array<string>;
  // Array
  received_lines: Array<string>;
  parent_types: Array<string>;
  report_types: Array<string>;
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
  // dates
  created: Date;
  published: Date;
  first_seen: Date;
  last_seen: Date;
  valid_from: Date;
  valid_until: Date;
  first_observed: Date;
  last_observed: Date;
  // boolean
  revoked: boolean;
  is_family: boolean;
  // number
  number_observed: number;
  confidence: number;
  latitude: number;
  longitude: number;
  precision: number;
  x_opencti_order: number;
}
interface StoreEntity extends BasicStoreEntity, StoreCommon {
  // inputs
  [INPUT_CREATED_BY]: StoreBasicEntity;
  [INPUT_RAW_EMAIL]: StoreBasicEntity;
  [INPUT_OBJECTS]: Array<StoreEntity>;
  [INPUT_LABELS]: Array<StoreLabel>;
  [INPUT_KILLCHAIN]: Array<StoreKillChainPhases>;
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
  // Array
  x_opencti_additional_names: Array<string>;
  received_lines: Array<string>;
  protocols: Array<string>;
  languages: Array<string>;
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
  // object
  ipfix: object;
  environment_variables: object;
}
interface StoreCyberObservable extends BasicStoreCyberObservable, StoreCommon {
  // inputs
  [INPUT_CONTAINS]: Array<BasicStoreEntity>;
  [INPUT_BODY_MULTIPART]: Array<BasicStoreEntity>;
  [INPUT_PARENT_DIRECTORY]: StoreBasicEntity;
  [INPUT_BODY_RAW]: BasicStoreEntity;
  [INPUT_SRC]: BasicStoreEntity;
  [INPUT_DST]: BasicStoreEntity;
  [INPUT_SRC_PAYLOAD]: BasicStoreEntity;
  [INPUT_DST_PAYLOAD]: BasicStoreEntity;
  [INPUT_ENCAPSULATED_BY]: BasicStoreEntity;
  [INPUT_CREATOR_USER]: BasicStoreEntity;
  [INPUT_IMAGE]: BasicStoreEntity;
  [INPUT_PARENT]: BasicStoreEntity;
  [INPUT_CHILD]: Array<BasicStoreEntity>;
  [INPUT_ENCAPSULATES]: Array<BasicStoreEntity>;
  [INPUT_OPENED_CONNECTION]: Array<BasicStoreEntity>;
  [INPUT_CC]: Array<BasicStoreEntity>;
  [INPUT_BCC]: Array<BasicStoreEntity>;
  [INPUT_TO]: Array<StoreBasicEntity>;
  [INPUT_RESOLVES_TO]: Array<BasicStoreEntity>;
  [INPUT_BELONGS_TO]: Array<BasicStoreEntity>;
  [INPUT_SENDER]: BasicStoreEntity;
  [INPUT_RAW_EMAIL]: BasicStoreEntity;
  [INPUT_FROM]: StoreBasicEntity;
  [INPUT_CONTENT]: StoreBasicEntity;
  [INPUT_VALUES]: Array<StoreWindowsRegistryValueType>;
  [INPUT_LABELS]: Array<StoreLabel>;
  [INPUT_EXTERNAL_REFS]: Array<StoreExternalReferences>;
}

interface BasicRuleEntity extends BasicStoreEntity {
  active: boolean;
}

interface BasicManagerEntity extends BasicStoreEntity {
  id: string;
  errors: Array<{
    error: string;
    source: Sstring;
    timestamp: Date;
  }>;
  lastEventId: string;
}

interface BasicTaskEntity extends BasicStoreEntity {
  completed: boolean;
  created_at: Date;
}

type BasicStoreObject = BasicStoreEntity | BasicStoreCyberObservable | BasicStoreRelation;
type StoreObject = StoreEntity | StoreCyberObservable | StoreRelation;
