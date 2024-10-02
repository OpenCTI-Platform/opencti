import ipaddr from 'ipaddr.js';
import { FunctionalError } from '../config/errors';
import { getExclusionListsByTypeFromCache, getExclusionListsByTypeFromCache2 } from '../database/cache';
import { exclusionListEntityType, ExclusionListProperties } from '../database/exclusionList/constants';

type ExtractedPattern = {
  type: string;
  value: string;
};

export const getIpAddrType = (range) => ipaddr.parse(range.split('/')[0]).kind();
export const getIsRange = (value) => value.indexOf('/') !== -1;

const checkIpAddrType = (ipAddr) => {
  const isIpv4 = ipAddr.indexOf('.') !== -1;
  const isIpv6 = ipAddr.indexOf(':') !== -1;

  return { isIpv4, isIpv6 };
};

export const convertIpv6ToBinary = (ipv6: string, isRange?: boolean, range?: number) => {
  let test = ipv6.split(':');
  const emptyFieldIndex = test.indexOf('');

  if (isRange && range) {
    const binary = ipv6
      .split(':')
      .map((t) => (t === '' ? '0' : t))
      .map((hex) => (parseInt(hex, 16).toString(2)).padStart(16, '0'))
      .join('');
    return binary.slice(0, range + 1);
  }

  if (emptyFieldIndex !== -1 && test.length < 8) {
    test = [
      ...test.slice(0, emptyFieldIndex + 1),
      ...Array(8 - test.length).fill('0'),
      ...test.slice(emptyFieldIndex + 1)
    ];
  }

  return test
    .map((t) => (t === '' ? '0' : t))
    .map((hex) => (parseInt(hex, 16).toString(2)).padStart(16, '0'))
    .join('');
};

export const convertIpv4ToBinary = (ipv4: string, isRange?: boolean, range?: number) => {
  const binary = ipv4.split('.').map((ip) => (parseInt(ip, 10).toString(2)).padStart(8, '0')).join('');
  if (isRange && range) {
    return binary.slice(0, range + 1);
  }
  return binary;
};

const checkRange = (parsedIpAddrToTest, test) => parsedIpAddrToTest.match(ipaddr.parseCIDR(test));

const throwExclusionListError = (value: string, listName: string) => {
  console.timeEnd();
  throw FunctionalError(`Indicator creation failed, this pattern (${value}) is contained on an exclusion list (${listName})`, { value });
};

const checkIpAddressLists = (ipToTest: string, exclusionList: ExclusionListProperties[]) => {
  exclusionList.forEach(({ name, list }) => {
    list.forEach((item) => {
      const parsedIpAddrToTest = ipaddr.parse(ipToTest);
      const ipAddrToTestType = parsedIpAddrToTest.kind();
      if (getIpAddrType(item) !== ipAddrToTestType) return;
      if (checkRange(parsedIpAddrToTest, item) || ipToTest === item) {
        console.log('item : ', item);
        throwExclusionListError(ipToTest, name);
      }
    });
  });
};

const checkIpAddressLists2 = (ipToTest: string, exclusionList: ExclusionListProperties[]) => {
  const { isIpv4 } = checkIpAddrType(ipToTest);
  const binary = isIpv4 ? convertIpv4ToBinary(ipToTest) : convertIpv6ToBinary(ipToTest);

  exclusionList.forEach(({ name, list }) => {
    list.forEach((item) => {
      if (binary.startsWith(item)) {
        console.log('item match : ', item);
        throwExclusionListError(ipToTest, name);
      }
    });
  });
};

export const checkPatternValidity = (extractedPattern: ExtractedPattern[]): void => {
  console.time();
  extractedPattern.forEach(({ type, value }) => {
    // const selectedExclusionLists = getExclusionListsByTypeFromCache(type);
    const selectedExclusionLists = getExclusionListsByTypeFromCache2(type);
    if (!selectedExclusionLists.length) return;
    if (type === exclusionListEntityType.IPV4_ADDR || type === exclusionListEntityType.IPV6_ADDR) {
      // checkIpAddressLists(value, selectedExclusionLists);
      checkIpAddressLists2(value, selectedExclusionLists);
    }
  });
};
