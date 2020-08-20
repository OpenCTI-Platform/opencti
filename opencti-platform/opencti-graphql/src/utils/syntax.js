export const checkObservableSyntax = (observableType, observableData) => {
  switch (observableType) {
    case 'Autonomous-System':
      if (!/^\d{0,10}$/.test(observableData.number)) {
        return 'AS followed by numbers';
      }
      break;
    case 'Directory':
      if (!/^(\w+\.?)*\w+$/.test(observableData.path)) {
        return 'Valid directory chars';
      }
      break;
    case 'Domain-Name':
      if (
        !/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/.test(
          observableData.value
        )
      ) {
        return 'Valid domain name';
      }
      break;
    case 'Hostname':
      if (
        !/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/.test(
          observableData.value
        )
      ) {
        return 'Valid hostname';
      }
      break;
    case 'Email-Addr':
      if (
        !/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(
          observableData.value
        )
      ) {
        return 'Valid email address';
      }
      break;
    case 'IPv4-Addr':
      if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(observableData.value)) {
        return 'Valid IPv4 address';
      }
      break;
    case 'IPv6-Addr':
      if (
        !/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/.test(
          observableData.value
        )
      ) {
        return 'Valid IPv6 address';
      }
      break;
    case 'Mac-Addr':
      if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(observableData.value)) {
        return 'Valid MAC address';
      }
      break;
    default:
      // TODO: return false
      return true;
  }
  return true;
};
