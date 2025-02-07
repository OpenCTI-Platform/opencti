import { type ExclusionListCacheItem } from '../database/exclusionListCache';
import { ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_URL } from '../schema/stixCyberObservable';

export const getIsRange = (value: string) => value.indexOf('/') !== -1;

export const checkIpAddrType = (ipAddr: string) => {
  const isIpv4 = ipAddr.split('.').length === 4;
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
    return binary.slice(0, range);
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
    return binary.slice(0, range);
  }
  return binary;
};

export interface ConvertedIpAddr {
  ipv4: { ranges: number[], values: string[] }
  ipv6: { ranges: number[], values: string[] }
}

export const convertIpAddr = (list: string[]) => {
  const ipAddrConverted: ConvertedIpAddr = { ipv4: { ranges: [], values: [] }, ipv6: { ranges: [], values: [] } };
  for (let i = 0; i < list.length; i += 1) {
    const value = list[i];
    const { isIpv4, isIpv6 } = checkIpAddrType(value);
    const isRange = getIsRange(value);
    if (isIpv4) {
      const range = isRange ? parseInt(value.split('/')[1], 10) : 32;
      const convertedValue = convertIpv4ToBinary(value, isRange, range);
      if (!ipAddrConverted.ipv4.ranges.includes(range)) {
        ipAddrConverted.ipv4.ranges.push(range);
      }
      ipAddrConverted.ipv4.values.push(convertedValue);
    }
    if (isIpv6) {
      const range = isRange ? parseInt(value.split('/')[1], 10) : 128;
      const convertedValue = convertIpv6ToBinary(value, isRange, range);
      if (!ipAddrConverted.ipv6.ranges.includes(range)) {
        ipAddrConverted.ipv6.ranges.push(range);
      }
      ipAddrConverted.ipv6.values.push(convertedValue);
    }
  }
  return ipAddrConverted;
};

// search valueToCheck in an ordered exclusionListValues. Time complexity O(log(n))
const binarySearchList = (exclusionListValues: string[], valueToCheck: string) => {
  let start = 0;
  let end = exclusionListValues.length - 1;

  // Iterate while start not meets end
  while (start <= end) {
    // Find the mid index
    const mid = Math.floor((start + end) / 2);
    const midValue = exclusionListValues[mid];

    // If element is present at mid, return True
    if (valueToCheck.toLowerCase() === midValue.toLowerCase()) {
      return true;
    }

    // Else look in left or right half accordingly
    if (midValue < valueToCheck) {
      start = mid + 1;
    } else {
      end = mid - 1;
    }
  }

  return false;
};

const checkIpExclusionLists = (ipToTest: string, exclusionList: ExclusionListCacheItem[]) => {
  const { isIpv4 } = checkIpAddrType(ipToTest);
  const binary = isIpv4 ? convertIpv4ToBinary(ipToTest) : convertIpv6ToBinary(ipToTest);

  for (let i = 0; i < exclusionList.length; i += 1) {
    const { id, values, ranges } = exclusionList[i];
    if (!ranges) {
      return null;
    }
    for (let j = 0; j < ranges.length; j += 1) {
      const range = ranges[j];
      const binaryRange = binary.slice(0, range);
      const isBinaryInList = binarySearchList(values, binaryRange);
      if (isBinaryInList) {
        return { value: ipToTest, listId: id };
      }
    }
  }
  return null;
};

const checkStringExclusionLists = (valueToTest: string, exclusionList: ExclusionListCacheItem[]) => {
  for (let i = 0; i < exclusionList.length; i += 1) {
    const { id, values } = exclusionList[i];
    const isValueInList = binarySearchList(values, valueToTest);
    if (isValueInList) {
      return { value: valueToTest, listId: id };
    }
  }
  return null;
};

// check domain/url value and all their subdomains
// i.e. for values like www.google.com, we want to check for www.google.com AND .google.com
const checkDomainExclusionLists = (valueToTest: string, exclusionList: ExclusionListCacheItem[]) => {
  const valueCheck = checkStringExclusionLists(valueToTest, exclusionList);
  if (valueCheck) {
    return valueCheck;
  }
  const valueToTestSplit = valueToTest.split('.');
  for (let j = 1; j < valueToTestSplit.length - 1; j += 1) {
    const subValue = `.${valueToTestSplit.slice(j).join('.')}`;
    const subValueCheck = checkStringExclusionLists(subValue, exclusionList);
    if (subValueCheck) {
      return subValueCheck;
    }
  }
  return null;
};

export const checkExclusionLists = (valueToTest: string, valueToTestType: string, allExclusionLists: ExclusionListCacheItem[]) => {
  const relatedExclusionLists = allExclusionLists.filter((e) => e.types.includes(valueToTestType));
  if (relatedExclusionLists.length === 0) {
    return null;
  }
  switch (valueToTestType) {
    case ENTITY_IPV4_ADDR:
    case ENTITY_IPV6_ADDR:
      return checkIpExclusionLists(valueToTest, relatedExclusionLists);
    case ENTITY_DOMAIN_NAME:
    case ENTITY_URL:
      return checkDomainExclusionLists(valueToTest, relatedExclusionLists);
    default:
      return checkStringExclusionLists(valueToTest, relatedExclusionLists);
  }
};
