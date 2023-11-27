import {
  ABSTRACT_STIX_CORE_OBJECT,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
  ABSTRACT_STIX_REF_RELATIONSHIP,
  INPUT_ASSIGNEE,
  INPUT_BORN_IN,
  INPUT_CREATED_BY,
  INPUT_ETHNICITY,
  INPUT_EXTERNAL_REFS,
  INPUT_GRANTED_REFS,
  INPUT_INTERNAL_FILES,
  INPUT_KILLCHAIN,
  INPUT_LABELS,
  INPUT_MARKINGS,
  INPUT_OBJECTS,
  INPUT_PARTICIPANT,
  INPUT_WORKS
} from './general';
import {
  ENTITY_TYPE_IDENTITY_INDIVIDUAL,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_IDENTITY_SYSTEM,
  ENTITY_TYPE_LOCATION_COUNTRY,
  isStixDomainObjectContainer,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation
} from './stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from './stixMetaObject';
import { ENTITY_TYPE_EVENT } from '../modules/event/event-types';
import { ENTITY_TYPE_INTERNAL_FILE, ENTITY_TYPE_USER, ENTITY_TYPE_WORK } from './internalObject';
import { schemaTypesDefinition } from './schema-types';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../modules/organization/organization-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../modules/threatActorIndividual/threatActorIndividual-types';
import type { Checker, RefAttribute } from './attribute-definition';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from './stixCyberObservable';
import { ATTRIBUTE_SAMPLE } from '../modules/malwareAnalysis/malwareAnalysis-types';

export const ABSTRACT_STIX_NESTED_REF_RELATIONSHIP = 'stix-nested-ref-relationship'; // Only for front usage

export const INPUT_OPERATING_SYSTEM = 'operatingSystems';
export const INPUT_SAMPLE = 'samples';
export const INPUT_CONTAINS = 'containsObservable';
export const INPUT_RESOLVES_TO = 'resolvesTo';
export const INPUT_BELONGS_TO = 'belongsTo';
export const INPUT_SENDER = 'emailSender';
export const INPUT_EMAIL_FROM = 'emailFrom';
export const INPUT_EMAIL_TO = 'emailTo';
export const INPUT_CC = 'emailCc';
export const INPUT_BCC = 'emailBcc';
export const INPUT_RAW_EMAIL = 'rawEmail';
export const INPUT_BODY_RAW = 'bodyRaw';
export const INPUT_PARENT_DIRECTORY = 'parentDirectory';
export const INPUT_CONTENT = 'obsContent';
export const INPUT_SRC = 'networkSrc';
export const INPUT_DST = 'networkDst';
export const INPUT_SRC_PAYLOAD = 'srcPayload';
export const INPUT_DST_PAYLOAD = 'dstPayload';
export const INPUT_ENCAPSULATES = 'networkEncapsulates';
export const INPUT_ENCAPSULATED_BY = 'encapsulatedBy';
export const INPUT_OPENED_CONNECTION = 'openedConnections';
export const INPUT_CREATOR_USER = 'creatorUser';
export const INPUT_IMAGE = 'processImage';
export const INPUT_PARENT = 'processParent';
export const INPUT_CHILD = 'processChild';
export const INPUT_BODY_MULTIPART = 'bodyMultipart';
export const INPUT_VALUES = 'winRegValues';
export const INPUT_SERVICE_DLL = 'serviceDlls';
export const INPUT_TRANSACTION_FROM = 'transactionFrom';
export const INPUT_TRANSACTION_TO = 'transactionTo';

export const RELATION_OPERATING_SYSTEM = 'operating-system';
export const RELATION_SAMPLE = 'sample';
export const RELATION_CONTAINS = 'contains';
export const RELATION_RESOLVES_TO = 'obs_resolves-to';
export const RELATION_BELONGS_TO = 'obs_belongs-to';
export const RELATION_FROM = 'from';
export const RELATION_SENDER = 'sender';
export const RELATION_TO = 'to';
export const RELATION_CC = 'cc';
export const RELATION_BCC = 'bcc';
export const RELATION_RAW_EMAIL = 'raw-email';
export const RELATION_BODY_RAW = 'body-raw';
export const RELATION_PARENT_DIRECTORY = 'parent-directory';
export const RELATION_CONTENT = 'obs_content';
export const RELATION_SRC = 'src';
export const RELATION_DST = 'dst';
export const RELATION_SRC_PAYLOAD = 'src-payload';
export const RELATION_DST_PAYLOAD = 'dst-payload';
export const RELATION_ENCAPSULATES = 'encapsulates';
export const RELATION_ENCAPSULATED_BY = 'encapsulated-by';
export const RELATION_OPENED_CONNECTION = 'opened-connection';
export const RELATION_CREATOR_USER = 'creator-user';
export const RELATION_IMAGE = 'image';
export const RELATION_PARENT = 'parent';
export const RELATION_CHILD = 'child';
export const RELATION_BODY_MULTIPART = 'body-multipart';
export const RELATION_VALUES = 'values';
export const RELATION_SERVICE_DLL = 'service-dll';

// -- RELATIONS REF ---

export const operatingSystems: RefAttribute = {
  name: INPUT_OPERATING_SYSTEM,
  type: 'ref',
  databaseName: RELATION_OPERATING_SYSTEM,
  stixName: 'operating_system_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  label: 'Operating System',
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_SOFTWARE],
};

export const samples: RefAttribute = {
  name: INPUT_SAMPLE,
  type: 'ref',
  databaseName: RELATION_SAMPLE,
  stixName: ATTRIBUTE_SAMPLE,
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  label: 'Samples',
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE],
};

export const contains: RefAttribute = {
  name: INPUT_CONTAINS,
  type: 'ref',
  databaseName: RELATION_CONTAINS,
  label: 'Contains observable',
  stixName: 'contains_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: ['Stix-Core-Object'],
};
export const resolvesTo: RefAttribute = {
  name: INPUT_RESOLVES_TO,
  type: 'ref',
  databaseName: RELATION_RESOLVES_TO,
  label: 'Resolves to',
  stixName: 'resolves_to_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR],
};
export const belongsTo: RefAttribute = {
  name: INPUT_BELONGS_TO,
  type: 'ref',
  databaseName: RELATION_BELONGS_TO,
  label: 'Belongs to',
  stixName: 'belongs_to_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_USER_ACCOUNT, ENTITY_AUTONOMOUS_SYSTEM],
};
export const from: RefAttribute = {
  name: INPUT_EMAIL_FROM,
  type: 'ref',
  databaseName: RELATION_FROM,
  label: 'Email from',
  stixName: 'from_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_EMAIL_ADDR],
};
export const sender: RefAttribute = {
  name: INPUT_SENDER,
  type: 'ref',
  databaseName: RELATION_SENDER,
  label: 'Sender',
  stixName: 'sender_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_EMAIL_ADDR],
};
export const to: RefAttribute = {
  name: INPUT_EMAIL_TO,
  type: 'ref',
  databaseName: RELATION_TO,
  label: 'Email to',
  stixName: 'to_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_EMAIL_ADDR],
};
export const cc: RefAttribute = {
  name: INPUT_CC,
  type: 'ref',
  databaseName: RELATION_CC,
  label: 'CC',
  stixName: 'cc_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_EMAIL_ADDR],
};
export const bcc: RefAttribute = {
  name: INPUT_BCC,
  type: 'ref',
  databaseName: RELATION_BCC,
  label: 'BCC',
  stixName: 'bcc_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_EMAIL_ADDR],
};
export const rawEmail: RefAttribute = {
  name: INPUT_RAW_EMAIL,
  type: 'ref',
  databaseName: RELATION_RAW_EMAIL,
  label: 'Raw email',
  stixName: 'raw_email_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_ARTIFACT],
};
export const bodyRaw: RefAttribute = {
  name: INPUT_BODY_RAW,
  type: 'ref',
  databaseName: RELATION_BODY_RAW,
  label: 'Body raw reference',
  stixName: 'body_raw_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE],
};
export const parentDirectory: RefAttribute = {
  name: INPUT_PARENT_DIRECTORY,
  type: 'ref',
  databaseName: RELATION_PARENT_DIRECTORY,
  label: 'Parent directory',
  stixName: 'parent_directory_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_DIRECTORY],
};
export const obsContent: RefAttribute = {
  name: INPUT_CONTENT,
  type: 'ref',
  databaseName: RELATION_CONTENT,
  label: 'Artifact content',
  stixName: 'content_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_ARTIFACT],
};
export const src: RefAttribute = {
  name: INPUT_SRC,
  type: 'ref',
  databaseName: RELATION_SRC,
  label: 'SRC',
  stixName: 'src_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR],
};
export const dst: RefAttribute = {
  name: INPUT_DST,
  type: 'ref',
  databaseName: RELATION_DST,
  label: 'DST',
  stixName: 'dst_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR],
};
export const srcPayload: RefAttribute = {
  name: INPUT_SRC_PAYLOAD,
  type: 'ref',
  databaseName: RELATION_SRC_PAYLOAD,
  label: 'SRC Payload',
  stixName: 'src_payload_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_ARTIFACT],
};
export const dstPayload: RefAttribute = {
  name: INPUT_DST_PAYLOAD,
  type: 'ref',
  databaseName: RELATION_DST_PAYLOAD,
  label: 'DST Payload',
  stixName: 'dst_payload_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_ARTIFACT],
};
export const encapsulates: RefAttribute = {
  name: INPUT_ENCAPSULATES,
  type: 'ref',
  databaseName: RELATION_ENCAPSULATES,
  label: 'Encapsulates',
  stixName: 'encapsulates_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_NETWORK_TRAFFIC],
};
export const encapsulatedBy: RefAttribute = {
  name: INPUT_ENCAPSULATED_BY,
  type: 'ref',
  databaseName: RELATION_ENCAPSULATED_BY,
  label: 'Encaspulated by',
  stixName: 'encapsulated_by_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_NETWORK_TRAFFIC],
};
export const openedConnections: RefAttribute = {
  name: INPUT_OPENED_CONNECTION,
  type: 'ref',
  databaseName: RELATION_OPENED_CONNECTION,
  label: 'Opened connection',
  stixName: 'opened_connection_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_NETWORK_TRAFFIC],
};
export const creatorUser: RefAttribute = {
  name: INPUT_CREATOR_USER,
  type: 'ref',
  databaseName: RELATION_CREATOR_USER,
  label: 'User account creator',
  stixName: 'creator_user_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_USER_ACCOUNT],
};
export const image: RefAttribute = {
  name: INPUT_IMAGE,
  type: 'ref',
  databaseName: RELATION_IMAGE,
  label: 'Image',
  stixName: 'image_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_STIX_FILE],
};
export const parent: RefAttribute = {
  name: INPUT_PARENT,
  type: 'ref',
  databaseName: RELATION_PARENT,
  label: 'Parent',
  stixName: 'parent_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_PROCESS],
};
export const child: RefAttribute = {
  name: INPUT_CHILD,
  type: 'ref',
  databaseName: RELATION_CHILD,
  label: 'Child',
  stixName: 'child_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_PROCESS],
};
export const bodyMultipart: RefAttribute = {
  name: INPUT_BODY_MULTIPART,
  type: 'ref',
  databaseName: RELATION_BODY_MULTIPART,
  label: 'Body multiplart',
  stixName: 'body_multipart',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_EMAIL_MIME_PART_TYPE],
};
export const values: RefAttribute = {
  name: INPUT_VALUES,
  type: 'ref',
  databaseName: RELATION_VALUES,
  label: 'Windows registry values',
  stixName: 'values_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_WINDOWS_REGISTRY_VALUE_TYPE],
};
// xOpenctiLinkedTo is deprecated, but ref definition is still needed for migration to work properly
export const xOpenctiLinkedTo: RefAttribute = {
  name: 'xOpenctiLinkedTo',
  type: 'ref',
  databaseName: 'x_opencti_linked-to',
  label: 'Linked to',
  stixName: 'x_opencti_linked_to_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  datable: true,
  isFilterable: false,
  toTypes: ['Stix-Core-Object'],
};
export const serviceDlls: RefAttribute = {
  name: INPUT_SERVICE_DLL,
  type: 'ref',
  databaseName: RELATION_SERVICE_DLL,
  label: 'DLL service',
  stixName: 'service_dll_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  datable: true,
  isFilterable: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  toTypes: [ENTITY_HASHED_OBSERVABLE_STIX_FILE],
};

export const STIX_REF_RELATIONSHIPS: RefAttribute[] = [
  operatingSystems,
  samples,
  contains,
  resolvesTo,
  belongsTo,
  from,
  sender,
  to,
  cc,
  bcc,
  rawEmail,
  bodyRaw,
  parentDirectory,
  obsContent,
  src,
  dst,
  srcPayload,
  dstPayload,
  encapsulates,
  encapsulatedBy,
  openedConnections,
  creatorUser,
  image,
  parent,
  child,
  bodyMultipart,
  values,
  xOpenctiLinkedTo, // deprecated, but needed for migration to work properly
  serviceDlls
];

// -- Meta relationships

export const RELATION_CREATED_BY = 'created-by';
export const RELATION_OBJECT_MARKING = 'object-marking';
export const RELATION_OBJECT_LABEL = 'object-label';

export const RELATION_OBJECT = 'object'; // object_refs
export const RELATION_EXTERNAL_REFERENCE = 'external-reference'; // external_references
export const RELATION_INTERNAL_FILE = 'internal-file'; // internal-file
export const RELATION_WORK = 'work'; // work
export const RELATION_KILL_CHAIN_PHASE = 'kill-chain-phase'; // kill_chain_phases
export const RELATION_GRANTED_TO = 'granted'; // granted_refs (OpenCTI)
export const RELATION_OBJECT_ASSIGNEE = 'object-assignee';
export const RELATION_OBJECT_PARTICIPANT = 'object-participant';
export const RELATION_BORN_IN = 'born-in'; // Extension (TIM)
export const RELATION_ETHNICITY = 'of-ethnicity'; // Extension (TIM)

// EXTERNAL

export const createdBy: RefAttribute = {
  name: INPUT_CREATED_BY,
  type: 'ref',
  databaseName: RELATION_CREATED_BY,
  stixName: 'created_by_ref',
  mandatoryType: 'customizable',
  editDefault: true,
  multiple: false,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Author',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_IDENTITY_INDIVIDUAL, ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_IDENTITY_SYSTEM, ENTITY_TYPE_IDENTITY_ORGANIZATION],
};

export const objectMarking: RefAttribute = {
  name: INPUT_MARKINGS,
  type: 'ref',
  databaseName: RELATION_OBJECT_MARKING,
  stixName: 'object_marking_refs',
  mandatoryType: 'customizable',
  editDefault: true,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Markings',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_MARKING_DEFINITION],
};

export const objects: RefAttribute = {
  name: INPUT_OBJECTS,
  type: 'ref',
  databaseName: RELATION_OBJECT,
  label: 'Contains',
  stixName: 'object_refs',
  mandatoryType: 'internal',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, fromType, _) {
    return isStixDomainObjectContainer(fromType);
  },
  datable: false,
  isFilterable: true,
  toTypes: [ABSTRACT_STIX_CORE_OBJECT],
};

export const objectOrganization: RefAttribute = {
  name: INPUT_GRANTED_REFS,
  type: 'ref',
  databaseName: RELATION_GRANTED_TO,
  label: 'Shared with',
  stixName: 'granted_refs',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, fromType, toType) {
    return !(fromType === ENTITY_TYPE_EVENT || isStixDomainObjectIdentity(fromType)
        || isStixDomainObjectLocation(fromType))
      && this.toTypes.includes(toType);
  },
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_IDENTITY_ORGANIZATION],
};

export const objectAssignee: RefAttribute = {
  name: INPUT_ASSIGNEE,
  type: 'ref',
  databaseName: RELATION_OBJECT_ASSIGNEE,
  stixName: 'object_assignee_refs',
  mandatoryType: 'customizable',
  editDefault: true,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Assignees',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_USER],
};

export const objectParticipant: RefAttribute = {
  name: INPUT_PARTICIPANT,
  type: 'ref',
  databaseName: RELATION_OBJECT_PARTICIPANT,
  stixName: 'object_participant_refs',
  mandatoryType: 'customizable',
  editDefault: true,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Participants',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_USER],
};

export const bornIn: RefAttribute = {
  name: INPUT_BORN_IN,
  type: 'ref',
  databaseName: RELATION_BORN_IN,
  stixName: 'born_in_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isRefExistingForTypes(this, fromType, toType) {
    return ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL === fromType && this.toTypes.includes(toType);
  },
  label: 'Born In',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_LOCATION_COUNTRY],
};

export const ethnicity: RefAttribute = {
  name: INPUT_ETHNICITY,
  type: 'ref',
  databaseName: RELATION_ETHNICITY,
  stixName: 'ethnicity_ref',
  mandatoryType: 'no',
  editDefault: false,
  multiple: false,
  upsert: true,
  isRefExistingForTypes(this, fromType, toType) {
    return ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL === fromType && this.toTypes.includes(toType);
  },
  label: 'Ethnicity',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_LOCATION_COUNTRY],
};

// INTERNAL

export const objectLabel: RefAttribute = {
  name: INPUT_LABELS,
  type: 'ref',
  databaseName: RELATION_OBJECT_LABEL,
  stixName: 'labels',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Label',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_LABEL],
};

export const work: RefAttribute = {
  name: INPUT_WORKS,
  type: 'ref',
  databaseName: RELATION_WORK,
  stixName: 'work',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Work',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_WORK]
};
export const internalFiles: RefAttribute = {
  name: INPUT_INTERNAL_FILES,
  type: 'ref',
  databaseName: RELATION_INTERNAL_FILE,
  stixName: 'internal_files',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Internal file',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_INTERNAL_FILE]
};

export const externalReferences: RefAttribute = {
  name: INPUT_EXTERNAL_REFS,
  type: 'ref',
  databaseName: RELATION_EXTERNAL_REFERENCE,
  stixName: 'external_references',
  mandatoryType: 'no',
  editDefault: false,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'External reference',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_EXTERNAL_REFERENCE],
};
export const killChainPhases: RefAttribute = {
  name: INPUT_KILLCHAIN,
  type: 'ref',
  databaseName: RELATION_KILL_CHAIN_PHASE,
  stixName: 'kill_chain_phases',
  mandatoryType: 'customizable',
  editDefault: true,
  multiple: true,
  upsert: true,
  isRefExistingForTypes(this, _, toType) {
    return this.toTypes.includes(toType);
  },
  label: 'Kill chain phase',
  datable: false,
  isFilterable: true,
  toTypes: [ENTITY_TYPE_KILL_CHAIN_PHASE],
};

export const META_RELATIONS: RefAttribute[] = [
  objectLabel,
  externalReferences,
  killChainPhases,
  createdBy,
  bornIn,
  ethnicity,
  objectMarking,
  objects,
  // OCTI
  objectOrganization,
  objectAssignee,
];

// Register
schemaTypesDefinition.register(
  ABSTRACT_STIX_REF_RELATIONSHIP,
  [...STIX_REF_RELATIONSHIPS, ...META_RELATIONS].map((arr) => arr.databaseName)
);

export const isStixRefRelationship = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_STIX_REF_RELATIONSHIP) || type === ABSTRACT_STIX_REF_RELATIONSHIP;

export const buildRelationRef = (relationRef: Omit<RefAttribute, 'isRefExistingForTypes'>, isRefExistingForTypes: Checker): RefAttribute => {
  return {
    ...relationRef,
    isRefExistingForTypes
  };
};

// retro-compatibility with cyber-observable-relationship
export const STIX_REF_RELATIONSHIP_TYPES = [ABSTRACT_STIX_META_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, ABSTRACT_STIX_REF_RELATIONSHIP];
