export const checkObservableSyntax = (observableType, observableValue) => {
  switch (observableType) {
    case 'autonomous-system':
      if (!/^AS\d{0,10}$/.test(observableValue)) {
        return '^AS\\d{0,10}$';
      }
      break;
    case 'directory':
      if (!/^(\w+\.?)*\w+$/.test(observableValue)) {
        return '^(\\w+\\.?)*\\w+$';
      }
      break;
    case 'file-md5':
      if (!/^[a-f0-9]{32}$/.test(observableValue)) {
        return '^[a-f0-9]{32}$';
      }
      break;
    case 'file-sha1':
      if (!/^[0-9a-f]{5,40}$/.test(observableValue)) {
        return '^[0-9a-f]{5,40}$';
      }
      break;
    case 'file-sha256':
      if (!/^[A-Fa-f0-9]{64}$/.test(observableValue)) {
        return '^[A-Fa-f0-9]{64}$';
      }
      break;
    case 'ipv4-addr':
      if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(observableValue)) {
        return '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$';
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
