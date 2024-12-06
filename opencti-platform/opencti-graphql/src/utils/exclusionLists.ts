import { ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR } from '../schema/stixCyberObservable';
import { MAX_EVENT_LOOP_PROCESSING_TIME } from '../database/utils';
import type { ExclusionListSlowCacheItem } from '../database/exclusionListCacheSlow';

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

export const convertIpAddr = (ipValue: string) => {
  const ipAddress = ipValue.split('/')[0];
  const { isIpv4, isIpv6 } = checkIpAddrType(ipAddress);
  if (!isIpv4 && !isIpv6) return ipValue;
  const isRange = getIsRange(ipValue);
  const ipAddressRangeValue = ipValue.split('/')?.[1] ?? '0';
  if (isIpv6) return convertIpv6ToBinary(ipAddress, isRange, parseInt(ipAddressRangeValue, 10));
  return convertIpv4ToBinary(ipAddress, isRange, parseInt(ipAddressRangeValue, 10));
};

export const checkIpAddressLists = async (ipToTest: string, exclusionList: ExclusionListSlowCacheItem[]) => {
  const { isIpv4 } = checkIpAddrType(ipToTest);
  const binary = isIpv4 ? convertIpv4ToBinary(ipToTest) : convertIpv6ToBinary(ipToTest);

  let startProcessingTime = new Date().getTime();
  for (let i = 0; i < exclusionList.length; i += 1) {
    const { id, values } = exclusionList[i];

    for (let j = 0; j < values.length; j += 1) {
      if (binary.startsWith(values[j])) {
        return [id];
      }
    }
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }

  return [];
};

export const checkExclusionList = async (valueToTest: string, exclusionList: ExclusionListSlowCacheItem[]) => {
  let startProcessingTime = new Date().getTime();

  for (let i = 0; i < exclusionList.length; i += 1) {
    const { id, values } = exclusionList[i];

    for (let j = 0; j < values.length; j += 1) {
      const isWildCard = values[j].startsWith('.');
      if ((isWildCard && valueToTest.endsWith(values[j])) || valueToTest === values[j]) {
        return [id];
      }

      if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
        startProcessingTime = new Date().getTime();
        await new Promise((resolve) => {
          setImmediate(resolve);
        });
      }
    }
  }
  return [];
};

export interface MatchedExclusionList {
  matchedId: string
  matchedTypes: string[]
}

export interface ExclusionListNode {
  matchedLists: MatchedExclusionList[]
  nextNodes: Map<string, ExclusionListNode>
}

export const addExclusionListToTree = async (currentTree: ExclusionListNode, exclusionListId: string, exclusionListTypes: string[], exclusionListFileContent: string) => {
  // Add a single value to current tree: navigate through tree with each value's char being the navigation step
  const addValueToTree = (exclusionListFileValue: string, isIPValue: boolean) => {
    let currentNode = currentTree;
    const convertedValue = isIPValue ? convertIpAddr(exclusionListFileValue) : exclusionListFileValue;
    for (let i = 0; i < convertedValue.length; i += 1) {
      // IP value are added to tree from start char to end char, whereas other values are added from end char to start char
      const currentChar = !isIPValue ? convertedValue[convertedValue.length - 1 - i] : convertedValue[i];
      // If a nextNode with current character exists, move to it, otherwise append a new nextNode with current character
      const nextNodeIfExists = currentNode.nextNodes.get(currentChar);
      if (nextNodeIfExists) {
        currentNode = nextNodeIfExists;
      } else {
        const nextNode = { matchedLists: [], nextNodes: new Map() };
        currentNode.nextNodes.set(currentChar, nextNode);
        currentNode = nextNode;
      }
    }
    let typesToInsert = exclusionListTypes;
    if (isIPValue) {
      const { isIpv4 } = checkIpAddrType(exclusionListFileValue);
      typesToInsert = isIpv4 ? [ENTITY_IPV4_ADDR] : [ENTITY_IPV6_ADDR];
    }
    currentNode.matchedLists.push({ matchedId: exclusionListId, matchedTypes: typesToInsert });
  };

  if (!exclusionListFileContent) return;
  const exclusionListFileValues = exclusionListFileContent?.split(/\r\n|\n/).map((l) => l.trim()).filter((l) => l);
  const isIpList = exclusionListTypes.some((t) => ENTITY_IPV4_ADDR === t || ENTITY_IPV6_ADDR === t);
  let startProcessingTime = new Date().getTime();
  for (let i = 0; i < exclusionListFileValues.length; i += 1) {
    addValueToTree(exclusionListFileValues[i], isIpList);
    // Prevent event loop locking more than MAX_EVENT_LOOP_PROCESSING_TIME
    if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
      startProcessingTime = new Date().getTime();
      await new Promise((resolve) => {
        setImmediate(resolve);
      });
    }
  }
};

export const checkExclusionListTree = (exclusionListTree: ExclusionListNode | null, valueToCheck: string, valueToCheckType: string) => {
  if (!exclusionListTree || !valueToCheck || !valueToCheckType) {
    return [];
  }

  const isIPType = valueToCheckType === ENTITY_IPV4_ADDR || valueToCheckType === ENTITY_IPV6_ADDR;
  let finalValueToCheck = valueToCheck;
  if (isIPType) {
    const { isIpv4 } = checkIpAddrType(valueToCheck);
    finalValueToCheck = isIpv4 ? convertIpv4ToBinary(valueToCheck) : convertIpv6ToBinary(valueToCheck);
  }

  let currentNode = exclusionListTree;
  for (let i = 0; i < finalValueToCheck.length; i += 1) {
    const currentChar = isIPType ? finalValueToCheck[i] : finalValueToCheck[finalValueToCheck.length - 1 - i];
    const nextNode = currentNode.nextNodes.get(currentChar);
    if (nextNode) {
      currentNode = nextNode;
    } else {
      return [];
    }
    if ((isIPType || currentChar === '.') && currentNode.matchedLists.some((l) => l.matchedTypes.includes(valueToCheckType))) {
      return currentNode.matchedLists.filter((l) => l.matchedTypes.includes(valueToCheckType));
    }
  }

  return currentNode.matchedLists.filter((l) => l.matchedTypes.includes(valueToCheckType));
};
