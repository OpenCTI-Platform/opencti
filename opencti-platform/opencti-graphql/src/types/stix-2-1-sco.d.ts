import type { CyberObjectExtension, StixOpenctiExtension, StixCyberObject, StixDate, StixId } from './stix-2-1-common';
import { STIX_EXT_OCTI, STIX_EXT_OCTI_SCO } from './stix-2-1-extensions';
import type { StixInternalExternalReference } from './stix-2-1-smo';

// Artifact Object Specific Properties
export interface ArtifactExtension extends CyberObjectExtension {
  additional_names: Array<string>;
}
// mime_type, payload_bin, url, hashes, encryption_algorithm, decryption_key
export interface StixArtifact extends StixCyberObject {
  mime_type: string; // optional
  payload_bin: string; // optional
  url: string; // optional
  hashes : { [k: string]: string }; // optional
  encryption_algorithm: string; // optional
  decryption_key: string; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO]: ArtifactExtension
  };
}

// AS Object Specific Properties
// number, name, rir
export interface StixAutonomousSystem extends StixCyberObject {
  number: number;
  name: string; // optional
  rir: string; // optional
}

// Directory Object Specific Properties
// path, path_enc, ctime, mtime, atime, contains_refs
export interface StixDirectory extends StixCyberObject {
  path: string;
  path_enc: string; // optional
  ctime: StixDate; // optional
  mtime: StixDate; // optional
  atime: StixDate; // optional
  contains_refs: Array<StixId>; // optional
}

// Domain Name Object Specific Properties
// value, resolves_to_refs
export interface StixDomainName extends StixCyberObject {
  value: string;
  resolves_to_refs: Array<StixId>; // optional
}

// Email Address Object Specific Properties
// value, display_name, belongs_to_ref
export interface StixEmailAddress extends StixCyberObject {
  value: string;
  display_name: string; // optional
  belongs_to_ref: StixId; // optional
}

// Email Message Object Specific Properties
export interface StixInternalEmailBodyMultipart {
  content_type: string;
  content_disposition: string;
  body: string;
  body_raw_ref: StixId | undefined;
}

export interface StixEmailBodyMultipart extends StixInternalEmailBodyMultipart, StixCyberObject {
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO] : { extension_type : 'new-sco' }
  };
}

// Email Message Object Specific Properties
export interface EmailMessageExtension extends CyberObjectExtension {
  contains_refs: Array<StixId>;
}
// is_multipart, date, content_type, from_ref, sender_ref, to_refs, cc_refs, bcc_refs,
// subject, received_lines, additional_header_fields, body, body_multipart, raw_email_ref
export interface StixEmailMessage extends StixCyberObject {
  is_multipart: boolean;
  date: StixDate; // optional - attribute_date
  content_type: string; // optional
  from_ref: StixId | undefined; // optional
  sender_ref: StixId | undefined; // optional
  to_refs: Array<StixId>; // optional
  cc_refs: Array<StixId>; // optional
  bcc_refs: Array<StixId>; // optional
  message_id: string; // optional
  subject: string; // optional
  received_lines: Array<string>; // optional
  additional_header_fields: object; // optional
  body: string; // optional
  body_multipart: Array<StixInternalEmailBodyMultipart>; // optional
  raw_email_ref: StixId | undefined; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO]: EmailMessageExtension;
  };
}

// File Object Specific Properties
export interface FileExtension extends CyberObjectExtension {
  additional_names: Array<string>;
}
// hashes, size, name, name_enc, magic_number_hex, mime_type, ctime, mtime, atime,
// parent_directory_ref, contains_refs, content_ref
export interface StixFile extends StixCyberObject {
  hashes: object; // optional
  size: number; // optional
  name: string; // optional
  name_enc: string; // optional
  magic_number_hex: string; // optional
  mime_type: string; // optional
  ctime: StixDate; // optional
  mtime: StixDate; // optional
  atime: StixDate; // optional
  parent_directory_ref: StixId | undefined; // optional
  contains_refs: Array<StixId>; // optional
  content_ref : StixId | undefined; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: FileExtension
    // Archive extension
    'archive-ext'?: {
      contains_refs: Array<StixId>; // optional
      comment : string; // optional
    }
    // NTFS Extension
    'ntfs-ext'?: {
      sid : string; // optional
      alternate_data_streams: Array<{
        name: string;
        hashes: object; // optional
        size: number; // optional
      }>; // optional
    }
    // PDF Extension
    'pdf-ext'?: {
      version: string; // optional
      is_optimized: boolean; // optional
      document_info_dict: object; // optional
      pdfid0: string; // optional
      pdfid1: string; // optional
    }
    // Raster Image Extension
    'raster-image-ext'?: {
      image_height: number; // optional
      image_width: number; // optional
      bits_per_pixel: number; // optional
      exif_tags: object; // optional
    }
    // TODO Windows™ PE Binary Extension
    // 'windows-pebinary-ext'?: {
    // TODO Windows™ PE Optional Header Type
    // 'windows-pe-optional-header-type'?: {
    // Windows™ PE Section Type
    'windows-pe-section-type'?: {
      name: string;
      size: number; // optional
      entropy: number; // optional
      hashes: object; // optional
    }
  };
}

// Custom object extension - Cryptocurrency Wallet
// value
export interface StixCryptocurrencyWallet extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension
    [STIX_EXT_OCTI_SCO] : { extension_type : 'new-sco' }
  }
}

// Simple custom object extension
// Custom object extension - Cryptographic Key
// value
export interface StixCryptographicKey extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtension
    [STIX_EXT_OCTI_SCO] : { extension_type : 'new-sco' }
  }
}

// Custom object extension - Hostname
// value
export interface StixHostname extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - Text
// value
export interface StixText extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - User Agent
// value
export interface StixUserAgent extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - Bank Account
// iban, bic, number
export interface StixBankAccount extends StixCyberObject {
  iban: string;
  bic: string;
  account_number: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type: 'new-sco' }
  }
}

// Custom object extension - Credential
// value
export interface StixCredential extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type: 'new-sco' }
  }
}

// Custom object extension - Tracking number
// value
export interface StixTrackingNumber extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type: 'new-sco' }
  }
}

// Custom object extension - Phone number
// value
export interface StixPhoneNumber extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - Credit Card
// number, expiration_date, cvv, holder_name
export interface StixPaymentCard extends StixCyberObject {
  card_number: string;
  expiration_date: StixDate;
  cvv: number;
  holder_name: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - IMEI
// value
export interface StixIMEI extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type: 'new-sco' }
  }
}

// Custom object extension - ICCID
// value
export interface StixICCID extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type: 'new-sco' }
  }
}

// Custom object extension - IMSI
// value
export interface StixIMSI extends StixCyberObject {
  value: string;
  description: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type: 'new-sco' }
  }
}

type StixExtendedObservable = StixCryptographicKey | StixHostname | StixText | StixUserAgent | StixEmailBodyMultipart | StixWindowsRegistryValueType;

// IPv4 Address Object Specific Properties
// value, resolves_to_refs, belongs_to_refs
export interface StixIPv4Address extends StixCyberObject {
  value: string;
  resolves_to_refs: Array<StixId>; // optional
  belongs_to_refs: Array<StixId>; // optional
}

// IPv6 Address Object Specific Properties
// value, resolves_to_refs, belongs_to_refs
export interface StixIPv6Address extends StixCyberObject {
  value: string;
  resolves_to_refs: Array<StixId>; // optional
  belongs_to_refs: Array<StixId>; // optional
}

// MAC Address Object Specific Properties
// value
export interface StixMacAddress extends StixCyberObject {
  value: string;
}

// Mutex Object Specific Properties
// name
export interface StixMutex extends StixCyberObject {
  name: string;
}

// Network Traffic Specific Properties
// start, end, is_active, src_ref, dst_ref, src_port, dst_port, protocols, src_byte_count,
// dst_byte_count, src_packets, dst_packets, ipfix, src_payload_ref, dst_payload_ref,
// encapsulates_refs, encapsulated_by_ref
// http-request-ext | icmp-ext | socket-ext | tcp-ext
type network_socket_address_family_enum = 'AF_UNSPEC' | 'AF_INET' | 'AF_IPX' | 'AF_APPLETALK' | 'AF_NETBIOS' | 'AF_INET6' | 'AF_IRDA' | 'AF_BTH';
type network_socket_type_enum = 'SOCK_STREAM' | 'AF_ISOCK_DGRAMNET' | 'SOCK_RAW' | 'SOCK_RDM' | 'SOCK_SEQPACKET';
export interface StixNetworkTraffic extends StixCyberObject {
  start: StixDate; // optional
  end: StixDate; // optional
  is_active: boolean; // optional
  src_ref: StixId | undefined; // optional
  dst_ref: StixId | undefined; // optional
  src_port: number; // optional
  dst_port: number; // optional
  protocols: Array<string>; // optional
  src_byte_count: number; // optional
  dst_byte_count: number; // optional
  src_packets: number; // optional
  dst_packets: number; // optional
  ipfix: object; // optional
  src_payload_ref: StixId | undefined; // optional
  dst_payload_ref: StixId | undefined; // optional
  encapsulates_refs: Array<StixId>; // optional
  encapsulated_by_ref: StixId | undefined; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]?: CyberObjectExtension
    // HTTP Request Extension
    'http-request-ext'?: {
      request_method: string;
      request_value : string;
      request_version : string; // optional
      request_header : object; // optional
      message_body_length: number; // optional
      message_body_data_ref: StixId; // optional
    }
    // ICMP Extension
    'icmp-ext'?: {
      icmp_type_hex: string;
      icmp_code_hex: string;
    }
    // Network Socket Extension
    'socket-ext'?: {
      address_family: network_socket_address_family_enum;
      is_blocking: boolean; // optional
      is_listening: boolean; // optional
      options: object; // optional
      socket_type: network_socket_type_enum; // optional
      socket_descriptor: number; // optional
      socket_handle: number; // optional
    }
    // TCP Extension
    'tcp-ext'?: {
      src_flags_hex: string; // optional
      dst_flags_hex : string; // optional
    }
  };
}

// Process Object Specific Properties
// is_hidden, pid, created_time, cwd, command_line, environment_variables, opened_connection_refs,
// creator_user_ref, image_ref, parent_ref, child_refs
// windows-process-ext | windows-service-ext
type windows_integrity_level_enum = 'low' | 'medium' | 'high' | 'system';
type windows_service_start_type_enum = 'SERVICE_AUTO_START' | 'SERVICE_BOOT_START' | 'SERVICE_DEMAND_START' | 'SERVICE_DISABLED' | 'SERVICE_SYSTEM_ALERT';
type windows_service_type_enum = 'SERVICE_KERNEL_DRIVER' | 'SERVICE_FILE_SYSTEM_DRIVER' | 'SERVICE_WIN32_OWN_PROCESS' | 'SERVICE_WIN32_SHARE_PROCESS';
type windows_service_status_enum = 'SERVICE_CONTINUE_PENDING' | 'SERVICE_PAUSE_PENDING' | 'SERVICE_PAUSED' | 'SERVICE_RUNNING' | 'SERVICE_START_PENDING' | 'SERVICE_STOP_PENDING' | 'SERVICE_STOPPED';
type ssh_key_type_enum = 'rsa' | 'ecdsa' | 'ed25519' | 'dsa';
export interface StixProcess extends StixCyberObject {
  is_hidden: boolean; // optional
  pid: number; // optional
  created_time: StixDate; // optional
  cwd: string; // optional
  command_line: string; // optional
  environment_variables: object; // optional
  opened_connection_refs: Array<StixId>; // optional
  creator_user_ref: StixId | undefined; // optional
  image_ref: StixId | undefined; // optional
  parent_ref: StixId | undefined; // optional
  child_refs: Array<StixId>; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]?: CyberObjectExtension
    // Windows™ Process Extension
    'windows-process-ext': {
      aslr_enabled: boolean; // optional
      dep_enabled: boolean; // optional
      priority: string; // optional
      owner_sid: string; // optional
      window_title: string; // optional
      startup_info: object; // optional
      integrity_level: windows_integrity_level_enum; // optional
    }
    // Windows™ Service Extension
    'windows-service-ext': {
      service_name: string; // optional
      descriptions: Array<string>; // optional
      display_name: string; // optional
      group_name: string; // optional
      start_type: windows_service_start_type_enum; // optional
      service_dll_refs: Array<StixId>; // optional
      service_type: windows_service_type_enum; // optional
      service_status: windows_service_status_enum; // optional
    }
  };
}

// Software Object Specific Properties
// name, cpe, swid, languages, vendor, version
export interface SoftwareExtension extends CyberObjectExtension {
  product: string;
}
export interface StixSoftware extends StixCyberObject {
  name: string;
  cpe: string; // optional
  swid: string; // optional
  languages: Array<string>; // optional
  vendor: string; // optional
  version: string; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO]: SoftwareExtension
  };
}

// URL Object Specific Properties
// value
export interface StixURL extends StixCyberObject {
  score: number;
  value: string; // optional
}

// User Account Object Specific Properties
// user_id, credential, account_login, account_type, display_name, is_service_account, is_privileged,
// can_escalate_privs, is_disabled, account_created, account_expires, credential_last_changed,
// account_first_login, account_last_login
// unix-account-ext
export interface StixUserAccount extends StixCyberObject {
  user_id: string; // optional
  credential: string; // optional
  account_login: string; // optional
  account_type: string; // optional
  display_name: string; // optional
  is_service_account: boolean; // optional
  is_privileged: boolean; // optional
  can_escalate_privs: boolean; // optional
  is_disabled: boolean; // optional
  account_created: StixDate; // optional
  account_expires: StixDate; // optional
  credential_last_changed: StixDate; // optional
  account_first_login: StixDate; // optional
  account_last_login: StixDate; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]?: CyberObjectExtension
    // UNIX™ Account Extension
    'unix-account-ext'?: {
      gid: number; // optional
      groups: Array<string>; // optional
      home_dir: string; // optional
      shell: string; // optional
    }
  };
}

// Windows™ Registry Value Type
export interface StixInternalWindowsRegistryValueType {
  name: string;
  data: string;
  data_type: string;
}
export interface StixWindowsRegistryValueType extends StixInternalWindowsRegistryValueType, StixCyberObject {
  labels: Array<string>;
  description: string;
  score: number;
  created_by_ref: StixId | undefined;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension;
    [STIX_EXT_OCTI_SCO] : { extension_type : 'new-sco' }
  };
}

// WindowsTM Registry Key Object Specific Properties
// key, values, modified_time, creator_user_ref, number_of_subkeys
export interface StixWindowsRegistryKey extends StixCyberObject {
  key: string; // optional
  values: Array<StixInternalWindowsRegistryValueType>; // optional
  modified_time: StixDate; // optional
  creator_user_ref: StixId | undefined; // optional
  number_of_subkeys: number; // optional
}

// is_self_signed, hashes, version, serial_number, signature_algorithm, issuer, validity_not_before,
// validity_not_after, subject, subject_public_key_algorithm, subject_public_key_modulus,
// subject_public_key_exponent, x509_v3_extensions
export interface StixX509Certificate extends StixCyberObject {
  is_self_signed: boolean; // optional
  hashes: object; // optional
  version: string; // optional
  serial_number: string; // optional
  signature_algorithm: string; // optional
  issuer: string; // optional
  validity_not_before: StixDate; // optional
  validity_not_after: StixDate; // optional
  subject: string; // optional
  subject_public_key_algorithm: string; // optional
  subject_public_key_modulus: string; // optional
  subject_public_key_exponent: number; // optional
  x509_v3_extensions: {
    basic_constraints: string; // optional
    name_constraints: string; // optional
    policy_constraints: string; // optional
    key_usage: string; // optional
    extended_key_usage: string; // optional
    subject_key_identifier: string; // optional
    authority_key_identifier: string; // optional
    subject_alternative_name: string; // optional
    issuer_alternative_name: string; // optional
    subject_directory_attributes: string; // optional
    crl_distribution_points: string; // optional
    inhibit_any_policy: string; // optional
    private_key_usage_period_not_before: StixDate; // optional
    private_key_usage_period_not_after: StixDate; // optional
    certificate_policies: string; // optional
    policy_mappings: string; // optional
  }
}

// Custom object extension - Media Content
// value
export interface StixMediaContent extends StixCyberObject {
  title: string;
  description: string;
  content: string;
  media_category: string;
  url: string;
  publication_date: StixDate;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - Persona
// persona_name, persona_type
export interface StixPersona extends StixCyberObject {
  persona_name: string;
  persona_type: string;
  score: number;
  labels: Array<string>;
  created_by_ref: StixId | undefined,
  object_marking_refs: Array<StixId>;
  external_references: Array<StixInternalExternalReference>;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}

// Custom object extension - SSH key
// key_type, public_key, fingerprint_sha256, fingerprint_md5, key_length, comment, created, expiration_date
export interface StixSSHKey extends StixCyberObject {
  key_type: string; // optional
  public_key: string; // optional
  fingerprint_sha256: string;
  fingerprint_md5: string; // optional
  key_length: number; // optional
  comment: string; // optional
  created: StixDate | undefined; // optional
  expiration_date: StixDate | undefined; // optional
  external_references: Array<StixInternalExternalReference>; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtension
    [STIX_EXT_OCTI_SCO]: { extension_type : 'new-sco' }
  }
}
