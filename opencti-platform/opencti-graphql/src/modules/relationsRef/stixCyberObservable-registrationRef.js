import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../schema/general';
import { bcc, belongsTo, bodyMultipart, bodyRaw, buildRelationRef, cc, child, contains, createdBy, creatorUser, dst, dstPayload, encapsulatedBy, encapsulates, externalReferences, from, image, objectLabel, objectMarking, objectOrganization, obsContent, openedConnections, parent, parentDirectory, rawEmail, resolvesTo, sender, serviceDlls, src, srcPayload, to, values, xOpenctiLinkedTo } from '../../schema/stixRefRelationship';
import { ENTITY_AUTONOMOUS_SYSTEM, ENTITY_DIRECTORY, ENTITY_DOMAIN_NAME, ENTITY_EMAIL_ADDR, ENTITY_EMAIL_MESSAGE, ENTITY_EMAIL_MIME_PART_TYPE, ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR, ENTITY_NETWORK_TRAFFIC, ENTITY_PROCESS, ENTITY_URL, ENTITY_USER_ACCOUNT, ENTITY_WINDOWS_REGISTRY_KEY, ENTITY_WINDOWS_REGISTRY_VALUE_TYPE } from '../../schema/stixCyberObservable';
import { getParentTypes } from '../../schema/schemaUtils';
// TODO: re-check with the stix documentation because some ref are reverse
schemaRelationsRefDefinition.registerRelationsRef(ABSTRACT_STIX_CYBER_OBSERVABLE, [createdBy, objectMarking, objectLabel, externalReferences, objectOrganization, xOpenctiLinkedTo]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DIRECTORY, [
    buildRelationRef(contains, (_, toType) => [ENTITY_DIRECTORY, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_DOMAIN_NAME, [
    buildRelationRef(resolvesTo, (_, toType) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MESSAGE, [
    buildRelationRef(from, (_, toType) => ENTITY_EMAIL_ADDR === toType),
    buildRelationRef(sender, (_, toType) => ENTITY_EMAIL_ADDR === toType),
    buildRelationRef(to, (_, toType) => ENTITY_EMAIL_ADDR === toType),
    buildRelationRef(cc, (_, toType) => ENTITY_EMAIL_ADDR === toType),
    buildRelationRef(bcc, (_, toType) => ENTITY_EMAIL_ADDR === toType),
    buildRelationRef(bodyMultipart, (_, toType) => ENTITY_EMAIL_MIME_PART_TYPE === toType),
    buildRelationRef(rawEmail, (_, toType) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
    buildRelationRef(contains, (_, toType) => [ENTITY_HASHED_OBSERVABLE_STIX_FILE, ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_URL, ENTITY_EMAIL_ADDR].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_ADDR, [
    buildRelationRef(belongsTo, (_, toType) => ENTITY_USER_ACCOUNT === toType)
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_EMAIL_MIME_PART_TYPE, [
    buildRelationRef(bodyRaw, (_, toType) => [ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE].includes(toType))
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_HASHED_OBSERVABLE_STIX_FILE, [
    buildRelationRef(contains, (_, toType) => getParentTypes(toType).includes(ABSTRACT_STIX_CYBER_OBSERVABLE)),
    buildRelationRef(parentDirectory, (_, toType) => ENTITY_DIRECTORY === toType),
    buildRelationRef(obsContent, (_, toType) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV4_ADDR, [
    buildRelationRef(resolvesTo, (_, toType) => ENTITY_MAC_ADDR === toType),
    buildRelationRef(belongsTo, (_, toType) => ENTITY_AUTONOMOUS_SYSTEM === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_IPV6_ADDR, [
    buildRelationRef(resolvesTo, (_, toType) => ENTITY_MAC_ADDR === toType),
    buildRelationRef(belongsTo, (_, toType) => ENTITY_AUTONOMOUS_SYSTEM === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_NETWORK_TRAFFIC, [
    buildRelationRef(src, (_, toType) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR].includes(toType)),
    buildRelationRef(dst, (_, toType) => [ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_MAC_ADDR].includes(toType)),
    buildRelationRef(srcPayload, (_, toType) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
    buildRelationRef(dstPayload, (_, toType) => ENTITY_HASHED_OBSERVABLE_ARTIFACT === toType),
    buildRelationRef(encapsulates, (_, toType) => ENTITY_NETWORK_TRAFFIC === toType),
    buildRelationRef(encapsulatedBy, (_, toType) => ENTITY_NETWORK_TRAFFIC === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_PROCESS, [
    buildRelationRef(openedConnections, (_, toType) => ENTITY_NETWORK_TRAFFIC === toType),
    buildRelationRef(creatorUser, (_, toType) => ENTITY_USER_ACCOUNT === toType),
    buildRelationRef(image, (_, toType) => ENTITY_HASHED_OBSERVABLE_STIX_FILE === toType),
    buildRelationRef(parent, (_, toType) => ENTITY_PROCESS === toType),
    buildRelationRef(child, (_, toType) => ENTITY_PROCESS === toType),
    buildRelationRef(serviceDlls, (_, toType) => ENTITY_HASHED_OBSERVABLE_STIX_FILE === toType),
]);
schemaRelationsRefDefinition.registerRelationsRef(ENTITY_WINDOWS_REGISTRY_KEY, [
    buildRelationRef(values, (_, toType) => ENTITY_WINDOWS_REGISTRY_VALUE_TYPE === toType),
    buildRelationRef(creatorUser, (_, toType) => ENTITY_USER_ACCOUNT === toType),
]);
