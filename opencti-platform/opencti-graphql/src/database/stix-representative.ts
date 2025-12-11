import { head } from 'ramda';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { getStixRepresentativeConverters } from './stix-2-1-converter';
import type * as SRO from '../types/stix-2-1-sro';
import type * as S from '../types/stix-2-1-common';
import { isBasicRelationship } from '../schema/stixRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_NOTE,
  ENTITY_TYPE_CONTAINER_OBSERVED_DATA,
  ENTITY_TYPE_CONTAINER_OPINION,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_COURSE_OF_ACTION,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
  ENTITY_TYPE_VULNERABILITY,
  isStixDomainObjectIdentity,
  isStixDomainObjectLocation,
  isStixDomainObjectThreatActor
} from '../schema/stixDomainObject';
import type * as SDO from '../types/stix-2-1-sdo';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL, ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import type * as SMO from '../types/stix-2-1-smo';
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
} from '../schema/stixCyberObservable';
import type * as SCO from '../types/stix-2-1-sco';
import { hashValue } from '../utils/format';
import { UnsupportedError } from '../config/errors';
import { isInternalObject } from '../schema/internalObject';
import { ENTITY_TYPE_INDICATOR, type StixIndicator } from '../modules/indicator/indicator-types';
import { isUserCanAccessStoreElement } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import type { BasicStoreCommon } from '../types/store';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';

export const extractStixRepresentative = (
  stix: S.StixObject,
  { fromRestricted = false, toRestricted = false }: { fromRestricted: boolean, toRestricted: boolean } = { fromRestricted: false, toRestricted: false },
  withArrowForRelationships = false,
): string => {
  const entityType = stix.extensions[STIX_EXT_OCTI].type;
  // region Modules
  const convertFn = getStixRepresentativeConverters(entityType);
  if (convertFn) {
    return convertFn(stix);
  }
  // endregion
  if (isInternalObject(entityType)) {
    const internal = stix as S.StixInternal;
    return internal.name ?? 'undefined';
  }
  // region Sighting
  if (isStixSightingRelationship(entityType)) {
    const sighting = stix as SRO.StixSighting;
    const fromValue = fromRestricted ? 'Restricted' : sighting.extensions[STIX_EXT_OCTI].sighting_of_value;
    const targetValue = toRestricted ? 'Restricted' : sighting.extensions[STIX_EXT_OCTI].where_sighted_values;
    return `${fromValue} sighted in/at ${targetValue}`;
  }
  // endregion
  // region Relationship
  if (isBasicRelationship(entityType)) {
    const relation = stix as SRO.StixRelation;
    const fromValue = fromRestricted ? 'Restricted' : relation.extensions[STIX_EXT_OCTI].source_value;
    const targetValue = toRestricted ? 'Restricted' : relation.extensions[STIX_EXT_OCTI].target_value;
    const separator = withArrowForRelationships ? '➡️' : relation.relationship_type;
    return `${fromValue} ${separator} ${targetValue}`;
  }
  // endregion
  // region Entities
  if (isStixDomainObjectIdentity(entityType)) {
    return (stix as SDO.StixIdentity).name;
  }
  if (isStixDomainObjectLocation(entityType)) {
    return (stix as SDO.StixLocation).name;
  }
  if (isStixDomainObjectThreatActor(entityType)) {
    return (stix as SDO.StixThreatActor).name;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_REPORT) {
    return (stix as SDO.StixReport).name;
  }
  if (entityType === ENTITY_TYPE_MALWARE) {
    return (stix as SDO.StixMalware).name;
  }
  if (entityType === ENTITY_TYPE_INFRASTRUCTURE) {
    return (stix as SDO.StixInfrastructure).name;
  }
  if (entityType === ENTITY_TYPE_ATTACK_PATTERN) {
    return (stix as SDO.StixAttackPattern).name;
  }
  if (entityType === ENTITY_TYPE_CAMPAIGN) {
    return (stix as SDO.StixCampaign).name;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_NOTE) {
    return (stix as SDO.StixNote).abstract;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_OPINION) {
    return (stix as SDO.StixOpinion).opinion;
  }
  if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
    const observed = stix as SDO.StixObservedData;
    const from = observed.first_observed ?? '-inf';
    const to = observed.last_observed ?? '+inf';
    return `${from} - ${to}`;
  }
  if (entityType === ENTITY_TYPE_COURSE_OF_ACTION) {
    return (stix as SDO.StixCourseOfAction).name;
  }
  if (entityType === ENTITY_TYPE_INCIDENT) {
    return (stix as SDO.StixIncident).name;
  }
  if (entityType === ENTITY_TYPE_INDICATOR) {
    return (stix as StixIndicator).name;
  }
  if (entityType === ENTITY_TYPE_INTRUSION_SET) {
    return (stix as SDO.StixIntrusionSet).name;
  }
  if (entityType === ENTITY_TYPE_TOOL) {
    return (stix as SDO.StixTool).name;
  }
  if (entityType === ENTITY_TYPE_VULNERABILITY) {
    return (stix as SDO.StixVulnerability).name;
  }
  // endregion
  // region meta entities
  if (entityType === ENTITY_TYPE_MARKING_DEFINITION) {
    return (stix as SMO.StixMarkingDefinition).name;
  }
  if (entityType === ENTITY_TYPE_LABEL) {
    return (stix as SMO.StixLabel).value;
  }
  if (entityType === ENTITY_TYPE_EXTERNAL_REFERENCE) {
    const externalRef = stix as SMO.StixExternalReference;
    return `${externalRef.source_name}${externalRef.external_id ? ` (${externalRef.external_id})` : ''}`;
  }
  if (entityType === ENTITY_TYPE_KILL_CHAIN_PHASE) {
    return (stix as SMO.StixKillChainPhase).kill_chain_name;
  }
  // endregion
  // region Meta observable
  if (entityType === ENTITY_WINDOWS_REGISTRY_VALUE_TYPE) {
    const registry = stix as SCO.StixWindowsRegistryValueType;
    return registry.name ?? registry.data ?? 'Unknown';
  }
  if (entityType === ENTITY_EMAIL_MIME_PART_TYPE) {
    return (stix as SCO.StixEmailBodyMultipart).description;
  }
  // endregion
  // region Observables
  if (entityType === ENTITY_HASHED_OBSERVABLE_ARTIFACT) {
    const artifact = stix as SCO.StixArtifact;
    return hashValue(artifact) ?? artifact.payload_bin ?? artifact.url ?? 'Unknown';
  }
  if (entityType === ENTITY_AUTONOMOUS_SYSTEM) {
    const autonomous = stix as SCO.StixAutonomousSystem;
    return autonomous.name ?? autonomous.number ?? 'unknown';
  }
  if (entityType === ENTITY_BANK_ACCOUNT) {
    const bankAccount = stix as SCO.StixBankAccount;
    return bankAccount.iban ?? bankAccount.account_number ?? 'Unknown';
  }
  if (entityType === ENTITY_CREDENTIAL) {
    return (stix as SCO.StixCredential).value ?? 'Unknown';
  }
  if (entityType === ENTITY_TRACKING_NUMBER) {
    return (stix as SCO.StixTrackingNumber).value ?? 'Unknown';
  }
  if (entityType === ENTITY_CRYPTOGRAPHIC_KEY) {
    return (stix as SCO.StixCryptographicKey).value ?? 'Unknown';
  }
  if (entityType === ENTITY_CRYPTOGRAPHIC_WALLET) {
    return (stix as SCO.StixCryptocurrencyWallet).value ?? 'Unknown';
  }
  if (entityType === ENTITY_DIRECTORY) {
    return (stix as SCO.StixDirectory).path ?? 'Unknown';
  }
  if (entityType === ENTITY_DOMAIN_NAME) {
    return (stix as SCO.StixDomainName).value ?? 'Unknown';
  }
  if (entityType === ENTITY_EMAIL_ADDR) {
    return (stix as SCO.StixEmailAddress).value ?? 'Unknown';
  }
  if (entityType === ENTITY_EMAIL_MESSAGE) {
    const email = stix as SCO.StixEmailMessage;
    return email.body ?? email.subject ?? 'Unknown';
  }
  if (entityType === ENTITY_HASHED_OBSERVABLE_STIX_FILE) {
    const file = stix as SCO.StixFile;
    return hashValue(file) ?? file.name ?? 'Unknown';
  }
  if (entityType === ENTITY_HOSTNAME) {
    return (stix as SCO.StixHostname).value ?? 'Unknown';
  }
  if (entityType === ENTITY_IPV4_ADDR) {
    return (stix as SCO.StixIPv4Address).value ?? 'Unknown';
  }
  if (entityType === ENTITY_IPV6_ADDR) {
    return (stix as SCO.StixIPv6Address).value ?? 'Unknown';
  }
  if (entityType === ENTITY_MAC_ADDR) {
    return (stix as SCO.StixMacAddress).value ?? 'Unknown';
  }
  if (entityType === ENTITY_MEDIA_CONTENT) {
    const media = stix as SCO.StixMediaContent;
    return media.content ?? media.title ?? media.url ?? 'Unknown';
  }
  if (entityType === ENTITY_PERSONA) {
    const persona = stix as SCO.StixPersona;
    return persona.persona_name ?? 'Unknown';
  }
  if (entityType === ENTITY_MUTEX) {
    return (stix as SCO.StixMutex).name ?? 'Unknown';
  }
  if (entityType === ENTITY_NETWORK_TRAFFIC) {
    return String((stix as SCO.StixNetworkTraffic).dst_port ?? 'Unknown');
  }
  if (entityType === ENTITY_PROCESS) {
    const process = stix as SCO.StixProcess;
    return String(process.pid ?? process.command_line ?? 'Unknown');
  }
  if (entityType === ENTITY_SOFTWARE) {
    return (stix as SCO.StixSoftware).name ?? 'Unknown';
  }
  if (entityType === ENTITY_TEXT) {
    return (stix as SCO.StixText).value ?? 'Unknown';
  }
  if (entityType === ENTITY_PHONE_NUMBER) {
    return (stix as SCO.StixPhoneNumber).value ?? 'Unknown';
  }
  if (entityType === ENTITY_PAYMENT_CARD) {
    const paymentCard = stix as SCO.StixPaymentCard;
    return paymentCard.card_number ?? paymentCard.holder_name ?? 'Unknown';
  }
  if (entityType === ENTITY_URL) {
    return (stix as SCO.StixURL).value ?? 'Unknown';
  }
  if (entityType === ENTITY_USER_ACCOUNT) {
    const userAccount = stix as SCO.StixUserAccount;
    return userAccount.account_login ?? userAccount.user_id ?? 'Unknown';
  }
  if (entityType === ENTITY_USER_AGENT) {
    return (stix as SCO.StixUserAgent).value ?? 'Unknown';
  }
  if (entityType === ENTITY_WINDOWS_REGISTRY_KEY) {
    return (stix as SCO.StixWindowsRegistryKey).key ?? 'Unknown';
  }
  if (entityType === ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE) {
    const x509 = stix as SCO.StixX509Certificate;
    return hashValue(x509) ?? x509.subject ?? x509.issuer ?? 'Unknown';
  }
  if (entityType === ENTITY_SSH_KEY) {
    const sshKey = stix as SCO.StixSSHKey;
    return sshKey.key_type ?? 'Unknown';
  }
  if (entityType === ENTITY_IMEI) {
    return (stix as SCO.StixIMEI).value ?? 'Unknown';
  }
  if (entityType === ENTITY_ICCID) {
    return (stix as SCO.StixICCID).value ?? 'Unknown';
  }
  if (entityType === ENTITY_IMSI) {
    return (stix as SCO.StixIMSI).value ?? 'Unknown';
  }
  // endregion
  throw UnsupportedError('No representative extractor available', { type: entityType });
};

// region: user access information extractors
// extract information from a sighting to have all the elements to check if a user has access to the from/to of the sighting
const extractUserAccessPropertiesFromSighting = (sighting: SRO.StixSighting) => {
  return [
    {
      [RELATION_OBJECT_MARKING]: sighting.extensions[STIX_EXT_OCTI].sighting_of_ref_object_marking_refs,
      [RELATION_GRANTED_TO]: sighting.extensions[STIX_EXT_OCTI].sighting_of_ref_granted_refs,
      entity_type: sighting.extensions[STIX_EXT_OCTI].sighting_of_type,
    } as BasicStoreCommon,
    {
      [RELATION_OBJECT_MARKING]: sighting.extensions[STIX_EXT_OCTI].where_sighted_refs_object_marking_refs,
      [RELATION_GRANTED_TO]: sighting.extensions[STIX_EXT_OCTI].where_sighted_refs_granted_refs,
      entity_type: head(sighting.extensions[STIX_EXT_OCTI].where_sighted_types),
    } as BasicStoreCommon
  ];
};

// extract information from a relationship to have all the elements to check if a user has access to the from/to of the relationship
const extractUserAccessPropertiesFromRelationship = (relation: SRO.StixRelation) => {
  return [
    {
      [RELATION_OBJECT_MARKING]: relation.extensions[STIX_EXT_OCTI].source_ref_object_marking_refs,
      [RELATION_GRANTED_TO]: relation.extensions[STIX_EXT_OCTI].source_ref_granted_refs,
      entity_type: relation.extensions[STIX_EXT_OCTI].source_type,
    } as BasicStoreCommon,
    {
      [RELATION_OBJECT_MARKING]: relation.extensions[STIX_EXT_OCTI].target_ref_object_marking_refs,
      [RELATION_GRANTED_TO]: relation.extensions[STIX_EXT_OCTI].target_ref_granted_refs,
      entity_type: relation.extensions[STIX_EXT_OCTI].target_type,
    } as BasicStoreCommon
  ];
};

// extract information from a stix object to have all the elements to check if a user has access to the object
const extractUserAccessPropertiesFromStixObject = (
  instance: S.StixObject | S.StixRelationshipObject
) => {
  if (isStixSightingRelationship(instance.extensions[STIX_EXT_OCTI].type)) {
    const sighting = instance as SRO.StixSighting;
    return extractUserAccessPropertiesFromSighting(sighting);
  }
  if (isStixCoreRelationship(instance.extensions[STIX_EXT_OCTI].type)) {
    const relation = instance as SRO.StixRelation;
    return extractUserAccessPropertiesFromRelationship(relation);
  }
  return [];
};

export const extractStixRepresentativeForUser = async (
  context: AuthContext,
  user: AuthUser,
  stix: S.StixObject,
  withArrowForRelationships = false,
) => {
  const [from, to] = extractUserAccessPropertiesFromStixObject(stix);
  const fromRestricted = from ? !(await isUserCanAccessStoreElement(context, user, from)) : false;
  const toRestricted = to ? !(await isUserCanAccessStoreElement(context, user, to)) : false;
  return extractStixRepresentative(stix, { fromRestricted, toRestricted }, withArrowForRelationships);
};
