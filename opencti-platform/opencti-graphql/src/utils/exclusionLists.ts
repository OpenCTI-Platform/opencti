import { type ExclusionListCacheItem } from '../database/exclusionListCache';

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

export const convertIpAddr = (list: string[]) => {
  return list.map((value) => {
    const ipAddress = value.split('/')[0];
    const { isIpv4, isIpv6 } = checkIpAddrType(ipAddress);
    if (!isIpv4 && !isIpv6) return value;
    const isRange = getIsRange(value);
    const ipAddressRangeValue = value.split('/')?.[1] ?? '0';
    if (isIpv6) return convertIpv6ToBinary(ipAddress, isRange, parseInt(ipAddressRangeValue, 10));
    return convertIpv4ToBinary(ipAddress, isRange, parseInt(ipAddressRangeValue, 10));
  });
};

// search valueToCheck in an ordered exclusionListValues. Time complexity O(log(n))
const binarySearchList = (exclusionListValues: string[], valueToCheck: string, isIpValue: boolean) => {
  let start = 0;
  let end = exclusionListValues.length - 1;

  // Iterate while start not meets end
  while (start <= end) {
    // Find the mid index
    const mid = Math.floor((start + end) / 2);
    const midValue = exclusionListValues[mid];

    // If element is present at mid, return True
    const isStartWithCheck = isIpValue || midValue.endsWith('.');
    if ((isStartWithCheck && valueToCheck.startsWith(midValue)) || valueToCheck === midValue) {
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

export const checkIpAddressLists = (ipToTest: string, exclusionList: ExclusionListCacheItem[]) => {
  const { isIpv4 } = checkIpAddrType(ipToTest);
  const binary = isIpv4 ? convertIpv4ToBinary(ipToTest) : convertIpv6ToBinary(ipToTest);

  for (let i = 0; i < exclusionList.length; i += 1) {
    const { id, values } = exclusionList[i];

    const isBinaryInList = binarySearchList(values, binary, true);
    if (isBinaryInList) {
      return { value: ipToTest, listId: id };
    }
  }
  return null;
};

export const reverseString = (originalSring: string) => {
  let x = '';

  for (let i = originalSring.length - 1; i >= 0; i -= 1) {
    x += originalSring[i];
  }

  return x;
};
export const checkExclusionList = (valueToTest: string, exclusionList: ExclusionListCacheItem[]) => {
  const valueToTestReverse = reverseString(valueToTest);
  for (let i = 0; i < exclusionList.length; i += 1) {
    const { id, values } = exclusionList[i];

    const isValueInList = binarySearchList(values, valueToTestReverse, false);
    if (isValueInList) {
      return { value: valueToTest, listId: id };
    }
  }
  return null;
};
