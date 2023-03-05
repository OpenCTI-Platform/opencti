import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../../schema/general';
import {
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../../schema/stixCyberObservable';
import {
  bcc,
  belongsTo,
  bodyMultipart,
  bodyRaw,
  cc,
  child,
  contains,
  creatorUser,
  dst,
  dstPayload,
  encapsulatedBy,
  encapsulates,
  from,
  image,
  obsContent,
  openedConnections,
  parent,
  parentDirectory,
  rawEmail,
  resolvesTo,
  sender,
  serviceDlls,
  src,
  srcPayload,
  to,
  values,
  xOpenctiLinkedTo
} from '../../schema/stixCyberObservableRelationship';

schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, [xOpenctiLinkedTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DIRECTORY, [contains]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE, [contains, parentDirectory, obsContent, bodyRaw]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DOMAIN_NAME, [resolvesTo, to]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV4_ADDR, [resolvesTo, belongsTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV6_ADDR, [resolvesTo, belongsTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MESSAGE, [from, sender, to, cc, bcc, rawEmail, bodyRaw, bodyMultipart]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_ADDR, [belongsTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MIME_PART_TYPE, [bodyMultipart]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_NETWORK_TRAFFIC, [src, dst, srcPayload, dstPayload, encapsulates, encapsulatedBy]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PROCESS, [openedConnections, creatorUser, image, parent, child, serviceDlls]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_KEY, [values, creatorUser]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_VALUE_TYPE, [values]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_ARTIFACT, [rawEmail, bodyRaw, obsContent]);
