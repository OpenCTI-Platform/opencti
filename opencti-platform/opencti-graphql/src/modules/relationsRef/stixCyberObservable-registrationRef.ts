import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import {
  bcc,
  belongsTo,
  bodyMultipart,
  bodyRaw,
  buildRelationRef,
  cc,
  child,
  contains,
  createdBy,
  creatorUser,
  dst,
  dstPayload,
  emailTo,
  encapsulatedBy,
  encapsulates,
  externalReferences,
  emailFrom,
  image,
  objectLabel,
  objectMarking,
  objectOrganization,
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
  values,
} from '../../schema/stixRefRelationship';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_BANK_ACCOUNT,
  ENTITY_CREDENTIAL,
  ENTITY_CRYPTOGRAPHIC_KEY,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_HOSTNAME,
  ENTITY_ICCID,
  ENTITY_IMEI,
  ENTITY_IMSI,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_MEDIA_CONTENT,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PAYMENT_CARD,
  ENTITY_PERSONA,
  ENTITY_PHONE_NUMBER,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_SSH_KEY,
  ENTITY_TEXT,
  ENTITY_TRACKING_NUMBER,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_USER_AGENT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../../schema/stixCyberObservable';
import { getParentTypes } from '../../schema/schemaUtils';

// TODO: re-check with the stix documentation because some ref are reverse

schemaRelationsRefDefinition.registerRelationsRef(
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  [createdBy, objectMarking, objectLabel, externalReferences, objectOrganization]
);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DIRECTORY, [
  buildRelationRef(contains, (_: string, toType: string) => [ENTITY_DIRECTORY, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DOMAIN_NAME, [
  buildRelationRef(resolvesTo, (_: string, toType: string) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MESSAGE, [
  buildRelationRef(emailFrom, (_: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(sender, (_: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(emailTo, (_: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(cc, (_: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(bcc, (_: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(bodyMultipart, (_: string, toType: string) => ENTITY_EMAIL_MIME_PART_TYPE === toType),
  buildRelationRef(rawEmail, (_: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
  buildRelationRef(contains, (_: string, toType: string) => [ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_URL, ENTITY_EMAIL_ADDR].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_ADDR, [
  buildRelationRef(belongsTo, (_: string, toType: string) => ENTITY_USER_ACCOUNT === toType)
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MIME_PART_TYPE, [
  buildRelationRef(bodyRaw, (_: string, toType: string) => [ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE, [
  buildRelationRef(contains, (_: string, toType: string) => getParentTypes(toType).includes(ABSTRACT_STIX_CYBER_OBSERVABLE)),
  buildRelationRef(parentDirectory, (_: string, toType: string) => ENTITY_DIRECTORY === toType),
  buildRelationRef(obsContent, (_: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV4_ADDR, [
  buildRelationRef(resolvesTo, (_: string, toType: string) => ENTITY_MAC_ADDR === toType),
  buildRelationRef(belongsTo, (_: string, toType: string) => ENTITY_AUTONOMOUS_SYSTEM === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV6_ADDR, [
  buildRelationRef(resolvesTo, (_: string, toType: string) => ENTITY_MAC_ADDR === toType),
  buildRelationRef(belongsTo, (_: string, toType: string) => ENTITY_AUTONOMOUS_SYSTEM === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_NETWORK_TRAFFIC, [
  buildRelationRef(src, (_: string, toType: string) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR].includes(toType)),
  buildRelationRef(dst, (_: string, toType: string) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR].includes(toType)),
  buildRelationRef(srcPayload, (_: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
  buildRelationRef(dstPayload, (_: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
  buildRelationRef(encapsulates, (_: string, toType: string) => ENTITY_NETWORK_TRAFFIC === toType),
  buildRelationRef(encapsulatedBy, (_: string, toType: string) => ENTITY_NETWORK_TRAFFIC === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PROCESS, [
  buildRelationRef(openedConnections, (_: string, toType: string) => ENTITY_NETWORK_TRAFFIC === toType),
  buildRelationRef(creatorUser, (_: string, toType: string) => ENTITY_USER_ACCOUNT === toType),
  buildRelationRef(image, (_: string, toType: string) => ENTITY_HASHED_OBSERVABLE_STIX_FILE === toType),
  buildRelationRef(parent, (_: string, toType: string) => ENTITY_PROCESS === toType),
  buildRelationRef(child, (_: string, toType: string) => ENTITY_PROCESS === toType),
  buildRelationRef(serviceDlls, (_: string, toType: string) => ENTITY_HASHED_OBSERVABLE_STIX_FILE === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_KEY, [
  buildRelationRef(values, (_: string, toType: string) => ENTITY_WINDOWS_REGISTRY_VALUE_TYPE === toType),
  buildRelationRef(creatorUser, (_: string, toType: string) => ENTITY_USER_ACCOUNT === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_URL, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_USER_AGENT, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_BANK_ACCOUNT, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_AUTONOMOUS_SYSTEM, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_CREDENTIAL, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_CRYPTOGRAPHIC_WALLET, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_CRYPTOGRAPHIC_KEY, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DIRECTORY, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HOSTNAME, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_MAC_ADDR, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_MEDIA_CONTENT, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_MUTEX, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PAYMENT_CARD, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PERSONA, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PHONE_NUMBER, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_SOFTWARE, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TEXT, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_TRACKING_NUMBER, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_USER_ACCOUNT, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_VALUE_TYPE, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_SSH_KEY, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IMEI, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_ICCID, []);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IMSI, []);
