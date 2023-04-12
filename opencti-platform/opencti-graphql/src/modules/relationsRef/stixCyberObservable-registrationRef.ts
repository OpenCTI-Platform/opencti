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
  encapsulatedBy,
  encapsulates,
  externalReferences,
  from,
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
  to,
  values,
  xOpenctiLinkedTo
} from '../../schema/stixRefRelationship';
import {
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE
} from '../../schema/stixCyberObservable';
import { getParentTypes } from '../../schema/schemaUtils';

// TODO: re-check with the stix documentation because some ref are reverse

schemaRelationsRefDefinition.registerRelationsRef(
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  [createdBy, objectMarking, objectLabel, externalReferences, objectOrganization, xOpenctiLinkedTo]
);

schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DIRECTORY, [
  buildRelationRef(contains, (fromType: string, toType: string) => [ENTITY_DIRECTORY, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DOMAIN_NAME, [
  buildRelationRef(resolvesTo, (fromType: string, toType: string) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MESSAGE, [
  buildRelationRef(from, (fromType: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(sender, (fromType: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(to, (fromType: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(cc, (fromType: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(bcc, (fromType: string, toType: string) => ENTITY_EMAIL_ADDR === toType),
  buildRelationRef(bodyMultipart, (fromType: string, toType: string) => ENTITY_EMAIL_MIME_PART_TYPE === toType),
  buildRelationRef(rawEmail, (fromType: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_ADDR, [
  buildRelationRef(belongsTo, (fromType: string, toType: string) => ENTITY_USER_ACCOUNT === toType)
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MIME_PART_TYPE, [
  buildRelationRef(bodyRaw, (fromType: string, toType: string) => [ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE, [
  buildRelationRef(contains, (fromType: string, toType: string) => getParentTypes(toType).includes(ABSTRACT_STIX_CYBER_OBSERVABLE)),
  buildRelationRef(parentDirectory, (fromType: string, toType: string) => ENTITY_DIRECTORY === toType),
  buildRelationRef(obsContent, (fromType: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV4_ADDR, [
  buildRelationRef(resolvesTo, (fromType: string, toType: string) => ENTITY_MAC_ADDR === toType),
  buildRelationRef(belongsTo, (fromType: string, toType: string) => ENTITY_AUTONOMOUS_SYSTEM === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV6_ADDR, [
  buildRelationRef(resolvesTo, (fromType: string, toType: string) => ENTITY_MAC_ADDR === toType),
  buildRelationRef(belongsTo, (fromType: string, toType: string) => ENTITY_AUTONOMOUS_SYSTEM === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_NETWORK_TRAFFIC, [
  buildRelationRef(src, (fromType: string, toType: string) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR].includes(toType)),
  buildRelationRef(dst, (fromType: string, toType: string) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR].includes(toType)),
  buildRelationRef(srcPayload, (fromType: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
  buildRelationRef(dstPayload, (fromType: string, toType: string) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
  buildRelationRef(encapsulates, (fromType: string, toType: string) => ENTITY_NETWORK_TRAFFIC === toType),
  buildRelationRef(encapsulatedBy, (fromType: string, toType: string) => ENTITY_NETWORK_TRAFFIC === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PROCESS, [
  buildRelationRef(openedConnections, (fromType: string, toType: string) => ENTITY_NETWORK_TRAFFIC === toType),
  buildRelationRef(creatorUser, (fromType: string, toType: string) => ENTITY_USER_ACCOUNT === toType),
  buildRelationRef(image, (fromType: string, toType: string) => ENTITY_HASHED_OBSERVABLE_STIX_FILE === toType),
  buildRelationRef(parent, (fromType: string, toType: string) => ENTITY_PROCESS === toType),
  buildRelationRef(child, (fromType: string, toType: string) => ENTITY_PROCESS === toType),
  buildRelationRef(serviceDlls, (fromType: string, toType: string) => ENTITY_HASHED_OBSERVABLE_STIX_FILE === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_KEY, [
  buildRelationRef(values, (fromType: string, toType: string) => ENTITY_WINDOWS_REGISTRY_VALUE_TYPE === toType),
  buildRelationRef(creatorUser, (fromType: string, toType: string) => ENTITY_USER_ACCOUNT === toType),
]);
