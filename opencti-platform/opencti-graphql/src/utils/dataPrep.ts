import { FunctionalError } from '../config/errors';
import { getExclusionListsByTypeFromCache, getExclusionListsByTypeFromCache2 } from '../database/cache';
import { exclusionListEntityType, ExclusionListProperties } from '../database/exclusionList/constants';

type ExtractedPattern = {
  type: string;
  value: string;
};

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

const throwExclusionListError = (value: string, listName: string) => {
  // console.timeEnd();
  throw FunctionalError(`Indicator creation failed, this pattern (${value}) is contained on an exclusion list (${listName})`, { value });
};

// let viewedLine = 0;

const checkIpAddressLists2 = (ipToTest: string, exclusionList: ExclusionListProperties[]) => {
  const { isIpv4 } = checkIpAddrType(ipToTest);
  const binary = isIpv4 ? convertIpv4ToBinary(ipToTest) : convertIpv6ToBinary(ipToTest);

  exclusionList.forEach(({ name, list }) => {
    list.forEach((line) => {
      // viewedLine += 1;
      if (binary.startsWith(line)) {
        // console.log('viewedLine match IP : ', viewedLine);
        // console.log('line match : ', line);
        // viewedLine = 0;
        throwExclusionListError(ipToTest, name);
      }
    });
  });
};

export const checkPatternValidity = (extractedPattern: ExtractedPattern[]): void => {
  console.time();
  extractedPattern.forEach(({ type, value }) => {
    // console.log('type : ', type);
    // console.log('value : ', value);
    const selectedExclusionLists = getExclusionListsByTypeFromCache2(type);
    // console.log('selectedExclusionLists : ', selectedExclusionLists.map((item) => item.name));
    if (!selectedExclusionLists.length) return;
    if (type === exclusionListEntityType.IPV4_ADDR || type === exclusionListEntityType.IPV6_ADDR) {
      checkIpAddressLists2(value, selectedExclusionLists);
    } else {
      selectedExclusionLists.forEach(({ name, list }) => {
        list.forEach((line) => {
          const isWildCard = line.startsWith('.');
          if ((isWildCard && value.endsWith(line)) || value === line) {
            // console.log('line match : ', line);
            // console.log('viewedLine match OTHER : ', viewedLine);
            // viewedLine = 0;
            throwExclusionListError(value, name);
          }
        });
      });
    }
  });
  // console.log('viewedLine no match : ', viewedLine);
  // viewedLine = 0;
};
