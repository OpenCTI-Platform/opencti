/* eslint-disable no-case-declarations,import/prefer-default-export */
import * as C from '../schema/stixCyberObservable';

export const checkObservableSyntax = (observableType, observableData) => {
  switch (observableType) {
    case C.ENTITY_AUTONOMOUS_SYSTEM:
      const systemChecker = /^\d{0,10}$/;
      if (!systemChecker.test(observableData.number)) return 'AS followed by numbers';
      break;
    case C.ENTITY_DIRECTORY:
      const directoryChecker = /^(\w+\.?)*\w+$/;
      if (!directoryChecker.test(observableData.path)) return 'Valid directory chars';
      break;
    case C.ENTITY_DOMAIN_NAME:
      const domainChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$/;
      if (!domainChecker.test(observableData.value)) return 'Valid domain name';
      break;
    case C.ENTITY_X_OPENCTI_HOSTNAME:
      const hostnameChecker = /^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$/;
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
