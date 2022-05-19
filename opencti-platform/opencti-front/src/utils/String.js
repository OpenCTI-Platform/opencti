import * as R from 'ramda';

export const truncate = (str, limit) => {
  if (str === undefined || str === null || str.length <= limit) {
    return str;
  }
  const trimmedStr = str.substr(0, limit);
  if (!trimmedStr.includes(' ')) {
    return `${trimmedStr}...`;
  }
  return `${trimmedStr.substr(
    0,
    Math.min(trimmedStr.length, trimmedStr.lastIndexOf(' ')),
  )}...`;
};

export const adaptFieldValue = (value) => {
  if (Array.isArray(value)) {
    return value;
  }
  if (R.isNil(value)) {
    return '';
  }
  return value.toString();
};

export const pascalize = (s) => s.replace(/(\w)(\w*)/g, (g0, g1, g2) => g1.toUpperCase() + g2.toLowerCase());

export const convertStixType = (s) => {
  let type = pascalize(s);
  if (type.includes('Opencti')) {
    type = type.replaceAll('Opencti', 'OpenCTI');
  }
  if (type.includes('Ipv')) {
    type = type.replaceAll('Ipv', 'IPv');
  }
  if (type === 'File' || type === 'Stixfile') {
    return 'StixFile';
  }
  return type;
};

export const isValidStixBundle = (bundle) => {
  try {
    const data = JSON.parse(bundle);
    return !!(data.objects && data.objects.length > 0);
  } catch (e) {
    return false;
  }
};

export const toB64 = (str) => window.btoa(unescape(encodeURIComponent(str)));

export const fromB64 = (str) => decodeURIComponent(escape(window.atob(str)));
