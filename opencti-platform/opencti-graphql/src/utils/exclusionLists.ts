import { MAX_EVENT_LOOP_PROCESSING_TIME } from '../database/utils';
import { FunctionalError } from '../config/errors';
import { getExclusionListsByTypeFromCache } from '../database/cache';
import { type ExtractedObservableValues, type ExclusionListProperties, exclusionListEntityType } from './exclusionListsTypes';

export const getIsRange = (value) => value.indexOf('/') !== -1;

export const checkIpAddrType = (ipAddr) => {
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

const throwExclusionListError = (value: string, listName: string) => {
  throw FunctionalError(`Indicator creation failed, this pattern (${value}) is contained on an exclusion list (${listName})`, { value });
};

export const convertIpAddr = (list) => {
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

export const checkIpAddressLists = async (ipToTest: string, exclusionList: ExclusionListProperties[]) => {
  const { isIpv4 } = checkIpAddrType(ipToTest);
  const binary = isIpv4 ? convertIpv4ToBinary(ipToTest) : convertIpv6ToBinary(ipToTest);

  let startProcessingTime = new Date().getTime();
  for (let i = 0; i < exclusionList.length; i += 1) {
    const { list, name } = exclusionList[i];

    for (let j = 0; j < list.length; j += 1) {
      if (binary.startsWith(list[j])) {
        throwExclusionListError(ipToTest, name);
      }

      if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
        startProcessingTime = new Date().getTime();
        await new Promise((resolve) => {
          setImmediate(resolve);
        });
      }
    }
  }
};

export const checkExclusionList = async (valueToTest: string, exclusionList: ExclusionListProperties[]) => {
  let startProcessingTime = new Date().getTime();

  for (let i = 0; i < exclusionList.length; i += 1) {
    const { list, name } = exclusionList[i];

    for (let j = 0; j < list.length; j += 1) {
      const isWildCard = list[j].startsWith('.');
      if ((isWildCard && valueToTest.endsWith(list[j])) || valueToTest === list[j]) {
        throwExclusionListError(valueToTest, name);
      }

      if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
        startProcessingTime = new Date().getTime();
        await new Promise((resolve) => {
          setImmediate(resolve);
        });
      }
    }
  }
};

export const checkPatternValidity = async (extractedObservableValues: ExtractedObservableValues[]) => {
  for (let i = 0; i < extractedObservableValues.length; i += 1) {
    const { type, value } = extractedObservableValues[i];
    const selectedExclusionLists = getExclusionListsByTypeFromCache(type);
    if (!selectedExclusionLists.length) return;
    if (type === exclusionListEntityType.IPV4_ADDR || type === exclusionListEntityType.IPV6_ADDR) {
      await checkIpAddressLists(value, selectedExclusionLists);
    } else {
      await checkExclusionList(value, selectedExclusionLists);
    }
  }
};
