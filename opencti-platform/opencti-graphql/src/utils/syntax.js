export const checkObservableSyntax = (observableType, observableValue) => {
  switch (observableType) {
    case 'autonomous-system':
      if (!/^AS\d{0,10}$/.test(observableValue)) {
        return 'AS followed by numbers';
      }
      break;
    case 'directory':
      if (!/^(\w+\.?)*\w+$/.test(observableValue)) {
        return 'Valid directory chars';
      }
      break;
    case 'domain':
      if (
        !/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/.test(
          observableValue
        )
      ) {
        return 'Valid domain name';
      }
      break;
    case 'email-address':
      if (
        !/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(
          observableValue
        )
      ) {
        return 'Valid email address';
      }
      break;
    case 'file-md5':
      if (!/^[a-f0-9]{32}$/.test(observableValue)) {
        return 'Valid MD5 hash';
      }
      break;
    case 'file-sha1':
      if (!/^[0-9a-f]{5,40}$/.test(observableValue)) {
        return 'Valid SHA1 hash';
      }
      break;
    case 'file-sha256':
      if (!/^[A-Fa-f0-9]{64}$/.test(observableValue)) {
        return 'Valid SHA256 hash';
      }
      break;
    case 'ipv4-addr':
      if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(observableValue)) {
        return 'Valid IPv4 address';
      }
      break;
    case 'ipv6-addr':
      if (
        !/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/.test(
          observableValue
        )
      ) {
        return 'Valid IPv6 address';
      }
      break;
    case 'mac-addr':
      if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(observableValue)) {
        return 'Valid MAC address';
      }
      break;
    default:
      // TODO: return false
      return true;
  }
  return true;
};

export const checkIndicatorSyntax = (indicatorPatternType, indicatorPattern) => {
  if (indicatorPatternType && indicatorPattern) {
    return true;
  }
  return false;
};
