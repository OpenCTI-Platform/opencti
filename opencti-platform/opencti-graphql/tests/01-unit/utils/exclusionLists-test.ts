import { describe, it, expect } from 'vitest';
import {
  convertIpAddr,
  checkIpAddrType,
  convertIpv4ToBinary,
  convertIpv6ToBinary,
  checkExclusionList,
  checkIpAddressLists,
  checkPatternValidity,
} from '../../../src/utils/exclusionLists';
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

const ipv4ListToTest = [
  '99.93.60.129',
  '99.95.233.129',
  '99.99.99.193',
  '99.86.96.0/20',
  '99.87.0.0/19',
  '99.87.32.0/22'
];
const ipv4ListResult = [
  '01100011010111010011110010000001',
  '01100011010111111110100110000001',
  '01100011011000110110001111000001',
  '01100011010101100110',
  '0110001101010111000',
  '0110001101010111001000'
];
const ipv6ListToTest = [
  '2a12:e342:200::2:1819',
  '2c0f:e8f8:2000:233::a39b:7123',
  '2c0f:f530::d00:188',
  '2c0f:fa18::/32',
  '2c0f:fce8::/33',
  '2c0f:fe08:10::/48'
];
const ipv6ListResult = [
  '00101010000100101110001101000010000000100000000000000000000000000000000000000000000000000000000000000000000000100001100000011001',
  '00101100000011111110100011111000001000000000000000000010001100110000000000000000000000000000000010100011100110110111000100100011',
  '00101100000011111111010100110000000000000000000000000000000000000000000000000000000000000000000000001101000000000000000110001000',
  '00101100000011111111101000011000',
  '001011000000111111111100111010000',
  '001011000000111111111110000010000000000000010000',
];
const ipListToTest = [
  '195.250.75.178',
  '72.19.20.12',
  '85.15.176.243',
  '1.116.0.0/15',
  '101.79.225.0/24',
  '213.166.82.0/24',
  '2001:148f:fffe::1',
  '2602:fba1:a00::100:1',
  '2a0c:8fc1:6441::412:ab34',
  '2001:1424::/48',
  '2600:9000:1036::/47',
  '2a02:e8::/32',
];
const ipListResult = [
  '11000011111110100100101110110010',
  '01001000000100110001010000001100',
  '01010101000011111011000011110011',
  '000000010111010',
  '011001010100111111100001',
  '110101011010011001010010',
  '00100000000000010001010010001111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000001',
  '00100110000000101111101110100001000010100000000000000000000000000000000000000000000000000000000000000001000000000000000000000001',
  '00101010000011001000111111000001011001000100000100000000000000000000000000000000000000000000000000000100000100101010101100110100',
  '001000000000000100010100001001000000000000000000',
  '00100110000000001001000000000000000100000011011',
  '00101010000000100000000011101000',
];

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
      it('should return a partial binary composed of fixed bits', () => {
        const result = convertIpv4ToBinary('100.42.176.0', true, 20);
        expect(result.toString()).toBe('01100100001010101011');
        expect(result.toString().length).toBe(20);
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
        const result = convertIpv6ToBinary('2001:1a68::d911:224', false);
        expect(result.toString()).toBe('00100000000000010001101001101000000000000000000000000000000000000000000000000000000000000000000011011001000100010000001000100100');
      });
    });

    describe('When I convert a range of IPV6 : 2c0f:f238::/32', () => {
      it('should return a partial binary composed of fixed bits', () => {
        const result = convertIpv6ToBinary('2c0f:f238::', true, 32);
        expect(result.toString()).toBe('00101100000011111111001000111000');
        expect(result.toString().length).toBe(32);
      });
    });
  });

  describe('convertIpAddr', () => {
    describe('When I have a list of Ipv4', () => {
      it('should return a converted array of binary', () => {
        const result = convertIpAddr(ipv4ListToTest);
        expect(JSON.stringify(result)).toBe(JSON.stringify(ipv4ListResult));
      });
    });

    describe('When I have a list of Ipv6', () => {
      it('should return a converted array of binary', () => {
        const result = convertIpAddr(ipv6ListToTest);
        expect(JSON.stringify(result)).toBe(JSON.stringify(ipv6ListResult));
      });
    });

    describe('When I have a list of Ipv4 and IPV6', () => {
      it('should return a converted array of binary', () => {
        const result = convertIpAddr(ipListToTest);
        expect(JSON.stringify(result)).toBe(JSON.stringify(ipListResult));
      });
    });
  });
});
