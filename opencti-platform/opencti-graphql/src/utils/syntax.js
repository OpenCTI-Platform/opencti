/* eslint-disable no-case-declarations,import/prefer-default-export */
import * as C from '../schema/stixCyberObservable';

export const checkObservableSyntax = (observableType, observableData) => {
  switch (observableType) {
    case C.ENTITY_AUTONOMOUS_SYSTEM:
      const systemChecker = /^\d{0,10}$/;
      if (!systemChecker.test(observableData.number)) return 'Must be numeric';
      break;
    case C.ENTITY_DOMAIN_NAME:
      const domainChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$/;
      if (!domainChecker.test(observableData.value)) return 'Valid domain name';
      break;
    case C.ENTITY_HASHED_OBSERVABLE_STIX_FILE:
    case C.ENTITY_HASHED_OBSERVABLE_ARTIFACT:
      if (observableData.hashes && observableData.hashes.MD5) {
        const md5Checker = /^[a-fA-F0-9]{32}$/;
        if (!md5Checker.test(observableData.hashes.MD5)) return 'Valid MD5 hash';
      }
      if (observableData.hashes && observableData.hashes['SHA-1']) {
        const sha1Checker = /^[a-fA-F0-9]{40}$/;
        if (!sha1Checker.test(observableData.hashes['SHA-1'])) return 'Valid SHA-1 hash';
      }
      if (observableData.hashes && observableData.hashes['SHA-256']) {
        const sha256checker = /^[a-fA-F0-9]{64}$/;
        if (!sha256checker.test(observableData.hashes['SHA-256'])) return 'Valid SHA-256 hash';
      }
      if (observableData.hashes && observableData.hashes['SHA-512']) {
        const sha512checker = /^[a-fA-F0-9]{128}$/;
        if (!sha512checker.test(observableData.hashes['SHA-512'])) return 'Valid SHA-512 hash';
      }
      break;
    case C.ENTITY_X_OPENCTI_HOSTNAME:
      const hostnameChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])$/;
      if (!hostnameChecker.test(observableData.value)) return 'Valid hostname';
      break;
    case C.ENTITY_EMAIL_ADDR:
      const emailChecker = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
      if (!emailChecker.test(observableData.value)) return 'Valid email address';
      break;
    case C.ENTITY_IPV4_ADDR:
      const ipv4Checker = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/([0-9]|[1-2][0-9]|3[0-2]))?$/.test(observableData.value);
      if (!ipv4Checker) return 'Valid IPv4 address';
      break;
    case C.ENTITY_IPV6_ADDR:
      const ipv6Checker = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/;
      if (!ipv6Checker.test(observableData.value)) return 'Valid IPv6 address';
      break;
    case C.ENTITY_MAC_ADDR:
      const macAddrChecker = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
      if (!macAddrChecker.test(observableData.value)) return 'Valid MAC address';
      break;
    default:
      return true;
  }
  return true;
};
