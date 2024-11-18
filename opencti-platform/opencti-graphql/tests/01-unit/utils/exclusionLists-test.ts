import { describe, expect, it } from 'vitest';
import { addExclusionListToTree, checkExclusionListTree, checkIpAddrType, convertIpAddr, convertIpv4ToBinary, convertIpv6ToBinary } from '../../../src/utils/exclusionLists';
import { ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR } from '../../../src/schema/stixCyberObservable';

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
const domainNameList = [
  '.amanath-bank.com',
  '.ambfinancial.com',
  '.rbs.co.uk',
  '.rbtl.de',
  '.google.com',
  '.rts.ch',
  'fttp-207-53-229-233.krrbi.aanchuuphan.net',
  'fudmiks.cust.smartspb.net',
  '46-145.206-83.static-ip.oleane.fr',
  '46-150-165-124.broadband.opcom.ru',
  'ns4.epidc.co.kr',
  'ns4.gamania.com',
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
    it('should convert IP correctly to binary', () => {
      const result = convertIpAddr('75.126.95.138');
      expect(result.toString()).toBe('01001011011111100101111110001010');

      const rangeResult = convertIpAddr('99.87.0.0/19');
      expect(rangeResult.toString()).toBe('0110001101010111000');

      const ipV6Result = convertIpAddr('2001:1a68::d911:224');
      expect(ipV6Result.toString()).toBe('00100000000000010001101001101000000000000000000000000000000000000000000000000000000000000000000011011001000100010000001000100100');

      const ipV6RangeResult = convertIpAddr('2c0f:fce8::/33');
      expect(ipV6RangeResult.toString()).toBe('001011000000111111111100111010000');
    });
  });

  describe('checkTree', () => {
    describe('When I check if an IPV4 is contained on tree', () => {
      it('should find if value is in tree', async () => {
        const exclusionListIP = { id: 'ipList', types: [ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR], values: ipListToTest.join('\n') };
        const exclusionListDomain = { id: 'domainList', types: [ENTITY_DOMAIN_NAME], values: domainNameList.join('\n') };
        const exclusionListTree = { matchedLists: [], nextNodes: new Map() };
        await addExclusionListToTree(exclusionListTree, exclusionListIP.id, exclusionListIP.types, exclusionListIP.values);
        await addExclusionListToTree(exclusionListTree, exclusionListDomain.id, exclusionListDomain.types, exclusionListDomain.values);

        const ipInListCheckResult = checkExclusionListTree(exclusionListTree, '72.19.20.12', ENTITY_IPV4_ADDR);
        expect(ipInListCheckResult.length).toBe(1);
        expect(ipInListCheckResult[0].matchedId).toBe(exclusionListIP.id);
        expect(ipInListCheckResult[0].matchedTypes.length).toBe(1);
        expect(ipInListCheckResult[0].matchedTypes[0]).toBe(ENTITY_IPV4_ADDR);

        const ipNotInListCheckResult = checkExclusionListTree(exclusionListTree, '72.19.20.14', ENTITY_IPV4_ADDR);
        expect(ipNotInListCheckResult.length).toBe(0);

        // should be in range 2001:1424::/48
        const ipInRangeCheckResult = checkExclusionListTree(exclusionListTree, '2001:1424:0000:0000:0000:0000:0010:0000', ENTITY_IPV6_ADDR);
        expect(ipInRangeCheckResult.length).toBe(1);
        expect(ipInRangeCheckResult[0].matchedId).toBe(exclusionListIP.id);
        expect(ipInRangeCheckResult[0].matchedTypes.length).toBe(1);
        expect(ipInRangeCheckResult[0].matchedTypes[0]).toBe(ENTITY_IPV6_ADDR);

        const domainInListCheckResult = checkExclusionListTree(exclusionListTree, 'fudmiks.cust.smartspb.net', ENTITY_DOMAIN_NAME);
        expect(domainInListCheckResult.length).toBe(1);
        expect(domainInListCheckResult[0].matchedId).toBe(exclusionListDomain.id);

        const domainWildcardInListCheckResult = checkExclusionListTree(exclusionListTree, 'www.google.com', ENTITY_DOMAIN_NAME);
        expect(domainWildcardInListCheckResult.length).toBe(1);
        expect(domainInListCheckResult[0].matchedId).toBe(exclusionListDomain.id);

        const domainNotInListCheckResult = checkExclusionListTree(exclusionListTree, 'www.googl.com', ENTITY_DOMAIN_NAME);
        expect(domainNotInListCheckResult.length).toBe(0);
      });
    });
  });
});
