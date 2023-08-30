import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_CYBER_OBSERVABLE_HASHED_OBSERVABLE, buildRefRelationKey, } from './general';
import { RELATION_RELATED_TO } from './stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';
import { schemaTypesDefinition } from './schema-types';
import { RELATION_CREATED_BY, RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from './stixRefRelationship';

export const ENTITY_AUTONOMOUS_SYSTEM = 'Autonomous-System';
export const ENTITY_DIRECTORY = 'Directory';
export const ENTITY_DOMAIN_NAME = 'Domain-Name';
export const ENTITY_EMAIL_ADDR = 'Email-Addr';
export const ENTITY_EMAIL_MESSAGE = 'Email-Message';
export const ENTITY_EMAIL_MIME_PART_TYPE = 'Email-Mime-Part-Type';
export const ENTITY_HASHED_OBSERVABLE_ARTIFACT = 'Artifact';
export const ENTITY_HASHED_OBSERVABLE_STIX_FILE = 'StixFile'; // Because File already used
export const ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE = 'X509-Certificate';
export const ENTITY_IPV4_ADDR = 'IPv4-Addr';
export const ENTITY_IPV6_ADDR = 'IPv6-Addr';
export const ENTITY_MAC_ADDR = 'Mac-Addr';
export const ENTITY_MUTEX = 'Mutex';
export const ENTITY_NETWORK_TRAFFIC = 'Network-Traffic';
export const ENTITY_PROCESS = 'Process';
export const ENTITY_SOFTWARE = 'Software';
export const ENTITY_URL = 'Url';
export const ENTITY_USER_ACCOUNT = 'User-Account';
export const ENTITY_WINDOWS_REGISTRY_KEY = 'Windows-Registry-Key';
export const ENTITY_WINDOWS_REGISTRY_VALUE_TYPE = 'Windows-Registry-Value-Type';
export const ENTITY_CRYPTOGRAPHIC_KEY = 'Cryptographic-Key'; // Custom
export const ENTITY_CRYPTOGRAPHIC_WALLET = 'Cryptocurrency-Wallet'; // Custom
export const ENTITY_HOSTNAME = 'Hostname'; // Custom
export const ENTITY_TEXT = 'Text'; // Custom
export const ENTITY_USER_AGENT = 'User-Agent'; // Custom
export const ENTITY_BANK_ACCOUNT = 'Bank-Account'; // Custom
export const ENTITY_PHONE_NUMBER = 'Phone-Number'; // Custom
export const ENTITY_PAYMENT_CARD = 'Payment-Card'; // Custom
export const ENTITY_MEDIA_CONTENT = 'Media-Content'; // Custom

const STIX_CYBER_OBSERVABLES_HASHED_OBSERVABLES = [
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
];
schemaTypesDefinition.register(ABSTRACT_STIX_CYBER_OBSERVABLE_HASHED_OBSERVABLE, STIX_CYBER_OBSERVABLES_HASHED_OBSERVABLES);
const STIX_CYBER_OBSERVABLES = [
  ENTITY_AUTONOMOUS_SYSTEM,
  ENTITY_DIRECTORY,
  ENTITY_DOMAIN_NAME,
  ENTITY_EMAIL_ADDR,
  ENTITY_EMAIL_MESSAGE,
  ENTITY_EMAIL_MIME_PART_TYPE,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_HASHED_OBSERVABLE_X509_CERTIFICATE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_MAC_ADDR,
  ENTITY_MUTEX,
  ENTITY_NETWORK_TRAFFIC,
  ENTITY_PROCESS,
  ENTITY_SOFTWARE,
  ENTITY_URL,
  ENTITY_USER_ACCOUNT,
  ENTITY_WINDOWS_REGISTRY_KEY,
  ENTITY_WINDOWS_REGISTRY_VALUE_TYPE,
  ENTITY_CRYPTOGRAPHIC_KEY,
  ENTITY_CRYPTOGRAPHIC_WALLET,
  ENTITY_HOSTNAME,
  ENTITY_USER_AGENT,
  ENTITY_TEXT,
  ENTITY_BANK_ACCOUNT,
  ENTITY_PHONE_NUMBER,
  ENTITY_PAYMENT_CARD,
  ENTITY_MEDIA_CONTENT,
];
schemaTypesDefinition.register(ABSTRACT_STIX_CYBER_OBSERVABLE, STIX_CYBER_OBSERVABLES);

export const isStixCyberObservableHashedObservable = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_STIX_CYBER_OBSERVABLE_HASHED_OBSERVABLE)
  || type === ABSTRACT_STIX_CYBER_OBSERVABLE_HASHED_OBSERVABLE;
export const isStixCyberObservable = (type: string) => schemaTypesDefinition.isTypeIncludedIn(type, ABSTRACT_STIX_CYBER_OBSERVABLE)
  || type === ABSTRACT_STIX_CYBER_OBSERVABLE;

export const stixCyberObservableOptions = {
  StixCyberObservablesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    objectLabel: buildRefRelationKey(RELATION_OBJECT_LABEL),
    relatedTo: buildRefRelationKey(RELATION_RELATED_TO),
    objects: buildRefRelationKey(RELATION_OBJECT),
    hasExternalReference: buildRefRelationKey(RELATION_EXTERNAL_REFERENCE),
    sightedBy: buildRefRelationKey(STIX_SIGHTING_RELATIONSHIP),
    hashes_MD5: 'hashes.MD5',
    hashes_SHA1: 'hashes.SHA-1',
    hashes_SHA256: 'hashes.SHA-256',
    hashes_SHA512: 'hashes.SHA-512',
    creator: 'creator_id',
  },
  StixCyberObservablesOrdering: {}
};
