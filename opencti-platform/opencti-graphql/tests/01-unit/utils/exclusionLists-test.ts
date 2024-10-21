import { describe, it, expect } from 'vitest';
import { convertIpAddr, checkIpAddrType, convertIpv4ToBinary, convertIpv6ToBinary } from '../../../src/utils/exclusionLists';
import { exclusionListEntityType, type ExclusionListProperties } from '../../../src/utils/exclusionListsTypes';
import * as exclusionList from '../../data/exclusionLists/index';

const STORE_EXCLUSION_LIST = [
  exclusionList.vpnIpv4List,
  exclusionList.vpnIpv6List,
  exclusionList.publicDnsHostNameList, // test
  exclusionList.publicDnsV4List,
  exclusionList.publicDnsV6List,
  exclusionList.openaiGptBotList,
  exclusionList.captivePortalsList,
  exclusionList.bankWebsiteList,
  exclusionList.googleBotList,
];

const STORE_EXCLUSION_LIST_BINARY = [];

export const convertAndFillExclusionList = () => {
  STORE_EXCLUSION_LIST.forEach((item: ExclusionListProperties) => {
    if (item.type.includes(exclusionListEntityType.IPV4_ADDR) || item.type.includes(exclusionListEntityType.IPV6_ADDR)) {
      const newList = convertIpAddr(item.list);
      STORE_EXCLUSION_LIST_BINARY.push({ ...item, list: newList });
      return;
    }
    STORE_EXCLUSION_LIST_BINARY.push(item);
  });
};

describe('Exclusion Lists', () => {
  describe('checkIpAddrType', () => {
    describe('When I check an ipv4 : 75.126.95.138', () => {
      it('should return ipv4 as true and ipv6 as false', () => {
        const { isIpv4, isIpv6 } = checkIpAddrType('75.126.95.138');
        expect(isIpv4).toBe(true);
        expect(isIpv6).toBe(false);
      });
    });

    describe('When I check an ipv6 : 2604:a880:400:d1::3c0:f001', () => {
      it('should return ipv4 as false and ipv6 as true', () => {
        const { isIpv4, isIpv6 } = checkIpAddrType('2604:a880:400:d1::3c0:f00');
        expect(isIpv4).toBe(false);
        expect(isIpv6).toBe(true);
      });
    });
  });

  describe('convertIpv4ToBinary', () => {
    describe('When I convert a complete IPV4 : 75.126.95.138', () => {
      it('should return a complete binary', () => {
        const result = convertIpv4ToBinary('75.126.95.138', false);
        expect(result.toString()).toBe('01001011011111100101111110001010');
      });
    });

    describe('When I convert a range of IPV4 : 100.42.176.0/20', () => {
      it('should return a partial binary composed by fixed bits', () => {
        const result = convertIpv4ToBinary('100.42.176.0', true, 20);
        expect(result.toString()).toBe('011001000010101010110');
      });
    });
  });

  describe('convertIpv6ToBinary', () => {
    describe('When I convert a complete IPV6 : 2001:19f0:7402:1574:5400:2ff:fe66:2cff', () => {
      it('should return a complete binary', () => {
        const result = convertIpv6ToBinary('2001:19f0:7402:1574:5400:2ff:fe66:2cff', false);
        expect(result.toString()).toBe('00100000000000010001100111110000011101000000001000010101011101000101010000000000000000101111111111111110011001100010110011111111');
      });
    });

    describe('When I convert a short IPV6 : 2001:1a68::d911:224', () => {
      it('should return a complete binary', () => {
        const result = convertIpv6ToBinary('2001:19f0:7402:1574:5400:2ff:fe66:2cff', false);
        expect(result.toString()).toBe('00100000000000010001101001101000000000000000000000000000000000000000000000000000000000000000000011011001000100010000001000100100');
      });
    });
  });
// 2c0f:f238::/32
});
