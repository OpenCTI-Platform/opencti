import type { StixCyberObject, StixDate, StixId } from './stix-2-0-common';
import type { StixInternalExternalReference } from './stix-2-0-smo';

// Artifact
export interface StixArtifact extends StixCyberObject {
  mime_type: string;
  payload_bin: string;
  url: string;
  hashes: { [k: string]: string };
  encryption_algorithm: string;
  decryption_key: string;
  x_opencti_additional_names: Array<string>;
}

// Autonomous System
export interface StixAutonomousSystem extends StixCyberObject {
  number: number;
  name: string;
  rir: string;
}

// Directory
export interface StixDirectory extends StixCyberObject {
  path: string;
  path_enc: string;
  ctime: StixDate;
  mtime: StixDate;
  atime: StixDate;
  contains_refs: Array<StixId>;
}

// Domain Name
export interface StixDomainName extends StixCyberObject {
  value: string;
  resolves_to_refs: Array<StixId>;
}

// Email Address
export interface StixEmailAddress extends StixCyberObject {
  value: string;
  display_name: string;
  belongs_to_ref: StixId;
}

// Email Body Multipart (internal helper)
export interface StixInternalEmailBodyMultipart {
  content_type: string;
  content_disposition: string;
  body: string;
  body_raw_ref: StixId | undefined;
}

// Email Mime Part Type
export interface StixEmailBodyMultipart extends StixCyberObject {
  content_type: string;
  content_disposition: string;
  body: string;
  body_raw_ref: StixId | undefined;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Email Message
export interface StixEmailMessage extends StixCyberObject {
  is_multipart: boolean;
  date: StixDate;
  content_type: string;
  from_ref: StixId;
  sender_ref: StixId;
  to_refs: Array<StixId>;
  cc_refs: Array<StixId>;
  bcc_refs: Array<StixId>;
  message_id: string;
  subject: string;
  received_lines: Array<string>;
  additional_header_fields: object;
  body: string;
  body_multipart: Array<StixInternalEmailBodyMultipart>;
  raw_email_ref: StixId;
  x_opencti_contains_refs: Array<StixId>;
}

// File
export interface StixFile extends StixCyberObject {
  hashes: { [k: string]: string };
  size: number;
  name: string;
  name_enc: string;
  magic_number_hex: string;
  mime_type: string;
  ctime: StixDate;
  mtime: StixDate;
  atime: StixDate;
  parent_directory_ref: StixId;
  contains_refs: Array<StixId>;
  content_ref: StixId;
  x_opencti_additional_names: Array<string>;
}

// IPv4 Address
export interface StixIPv4Address extends StixCyberObject {
  value: string;
  resolves_to_refs: Array<StixId>;
  belongs_to_refs: Array<StixId>;
}

// IPv6 Address
export interface StixIPv6Address extends StixCyberObject {
  value: string;
  resolves_to_refs: Array<StixId>;
  belongs_to_refs: Array<StixId>;
}

// Mac Address
export interface StixMacAddress extends StixCyberObject {
  value: string;
}

// Mutex
export interface StixMutex extends StixCyberObject {
  name: string;
}

// Network Traffic
export interface StixNetworkTraffic extends StixCyberObject {
  start: StixDate;
  end: StixDate;
  is_active: boolean;
  src_ref: StixId;
  dst_ref: StixId;
  src_port: number;
  dst_port: number;
  protocols: Array<string>;
  src_byte_count: number;
  dst_byte_count: number;
  src_packets: number;
  dst_packets: number;
  ipfix: object;
  src_payload_ref: StixId;
  dst_payload_ref: StixId;
  encapsulates_refs: Array<StixId>;
  encapsulated_by_ref: StixId;
}

// Process
export interface StixProcess extends StixCyberObject {
  is_hidden: boolean;
  pid: number;
  created_time: StixDate;
  cwd: string;
  command_line: string;
  environment_variables: object;
  opened_connection_refs: Array<StixId>;
  creator_user_ref: StixId;
  image_ref: StixId;
  parent_ref: StixId;
  child_refs: Array<StixId>;
  // windows extensions as flat properties
  aslr_enabled: boolean;
  dep_enabled: boolean;
  priority: string;
  owner_sid: string;
  window_title: string;
  startup_info: object;
  integrity_level: string;
  service_name: string;
  descriptions: Array<string>;
  display_name: string;
  group_name: string;
  start_type: string;
  service_dll_refs: Array<StixId>;
  service_type: string;
  service_status: string;
}

// Software
export interface StixSoftware extends StixCyberObject {
  name: string;
  cpe: string;
  swid: string;
  languages: Array<string>;
  vendor: string;
  version: string;
  x_opencti_product: string;
}

// URL
export interface StixURL extends StixCyberObject {
  value: string;
  score: number;
}

// User Account
export interface StixUserAccount extends StixCyberObject {
  user_id: string;
  credential: string;
  account_login: string;
  account_type: string;
  display_name: string;
  is_service_account: boolean;
  is_privileged: boolean;
  can_escalate_privs: boolean;
  is_disabled: boolean;
  account_created: StixDate;
  account_expires: StixDate;
  credential_last_changed: StixDate;
  account_first_login: StixDate;
  account_last_login: StixDate;
}

// Windows Registry Key
export interface StixInternalWindowsRegistryValueType {
  name: string;
  data: string;
  data_type: string;
}

export interface StixWindowsRegistryKey extends StixCyberObject {
  key: string;
  values: Array<StixInternalWindowsRegistryValueType>;
  modified_time: StixDate;
  creator_user_ref: StixId;
  number_of_subkeys: number;
}

// Windows Registry Value Type (standalone)
export interface StixWindowsRegistryValueType extends StixCyberObject {
  name: string;
  data: string;
  data_type: string;
}

// X509 Certificate
export interface StixX509Certificate extends StixCyberObject {
  is_self_signed: boolean;
  hashes: { [k: string]: string };
  version: string;
  serial_number: string;
  signature_algorithm: string;
  issuer: string;
  validity_not_before: StixDate;
  validity_not_after: StixDate;
  subject: string;
  subject_public_key_algorithm: string;
  subject_public_key_modulus: string;
  subject_public_key_exponent: number;
  x509_v3_extensions: object;
}

// --- Custom OpenCTI observables ---

// Cryptocurrency Wallet
export interface StixCryptocurrencyWallet extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Cryptographic Key
export interface StixCryptographicKey extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Hostname
export interface StixHostname extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Text
export interface StixText extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Credential
export interface StixCredential extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// User Agent
export interface StixUserAgent extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Bank Account
export interface StixBankAccount extends StixCyberObject {
  iban: string;
  bic: string;
  account_number: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Tracking Number
export interface StixTrackingNumber extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Phone Number
export interface StixPhoneNumber extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Payment Card
export interface StixPaymentCard extends StixCyberObject {
  card_number: string;
  expiration_date: StixDate;
  cvv: number;
  holder_name: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Media Content
export interface StixMediaContent extends StixCyberObject {
  title: string;
  description: string;
  content: string;
  media_category: string;
  url: string;
  publication_date: StixDate;
  labels: Array<string>;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// Persona
export interface StixPersona extends StixCyberObject {
  persona_name: string;
  persona_type: string;
  labels: Array<string>;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// SSH Key
export interface StixSSHKey extends StixCyberObject {
  key_type: string;
  public_key: string;
  fingerprint_sha256: string;
  fingerprint_md5: string;
  key_length: number;
  comment: string;
  created: StixDate;
  expiration_date: StixDate;
  external_references: Array<StixInternalExternalReference>;
}

// AI Prompt
export interface StixAIPrompt extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// IMEI
export interface StixIMEI extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// ICCID
export interface StixICCID extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}

// IMSI
export interface StixIMSI extends StixCyberObject {
  value: string;
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
}
