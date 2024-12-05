import { describe, expect, it } from 'vitest';
import {
  addExclusionListToTree,
  checkExclusionList,
  checkExclusionListTree,
  checkIpAddressLists,
  checkIpAddrType,
  convertIpAddr,
  convertIpv4ToBinary,
  convertIpv6ToBinary
} from '../../../src/utils/exclusionLists';
import { ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_URL } from '../../../src/schema/stixCyberObservable';

const ipv4ListResult = [
  '01100011010111010011110010000001', // 99.93.60.129
  '01100011010111111110100110000001', // 99.95.233.129
  '01100011011000110110001111000001', // 99.99.99.193
  '01100011010101100110', // 99.86.96.0/20
  '0110001101010111000', // 99.87.0.0/19
  '0110001101010111001000' // 99.87.32.0/22
];
const ipv6ListResult = [
  '00101010000100101110001101000010000000100000000000000000000000000000000000000000000000000000000000000000000000100001100000011001', // 2a12:e342:200::2:1819
  '00101100000011111110100011111000001000000000000000000010001100110000000000000000000000000000000010100011100110110111000100100011', // 2c0f:e8f8:2000:233::a39b:7123
  '00101100000011111111010100110000000000000000000000000000000000000000000000000000000000000000000000001101000000000000000110001000', // 2c0f:f530::d00:188
  '00101100000011111111101000011000', // 2c0f:fa18::/32
  '001011000000111111111100111010000', // 2c0f:fce8::/33
  '001011000000111111111110000010000000000000010000', // 2c0f:fe08:10::/48
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
const ipv4ExclusionList = [{
  id: 'ipv4ListResult',
  types: [ENTITY_IPV4_ADDR],
  values: ipv4ListResult
}];
const ipv6ExclusionList = [{
  id: 'ipv6ListResult',
  types: [ENTITY_IPV6_ADDR],
  values: ipv6ListResult
}];
const domainExclusionList = [{
  id: 'domainExclusionList',
  types: [ENTITY_DOMAIN_NAME, ENTITY_URL],
  values: domainNameList
}];
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
  describe('checkIpAddressLists', () => {
    describe('When I check if an IPV4 is contained on lists', () => {
      describe('99.99.99.193', () => {
        it('should throw an error', async () => {
          const result = await checkIpAddressLists('99.99.99.193', ipv4ExclusionList);
          expect(result.length).toBe(1);
          expect(result[0]).toBe('ipv4ListResult');
        });
      });

      describe('99.87.23.11', () => {
        it('should throw an error', async () => {
          const result = await checkIpAddressLists('99.87.23.11', ipv4ExclusionList);
          expect(result.length).toBe(1);
          expect(result[0]).toBe('ipv4ListResult');
        });
      });

      describe('22.22.22.22', () => {
        it('should do nothing', async () => {
          const result = await checkIpAddressLists('22.22.22.22', ipv4ExclusionList);
          expect(result.length).toBe(0);
        });
      });
    });

    describe('When I check if an IPV6 is contained on lists', () => {
      describe('2a12:e342:200::2:1819', () => {
        it('should throw an error', async () => {
          const result = await checkIpAddressLists('2a12:e342:200::2:1819', ipv6ExclusionList);
          expect(result.length).toBe(1);
          expect(result[0]).toBe('ipv6ListResult');
        });
      });

      describe('2602:fba1:a00::100:19', () => {
        it('should do nothing', async () => {
          const result = await checkExclusionList('2602:fba1:a00::100:19', ipv6ExclusionList);
          expect(result.length).toBe(0);
        });
      });
    });
  });

  describe('checkExclusionList', () => {
    describe('When I check if a domain name is contained on lists', () => {
      describe('ns4.epidc.co.kr', () => {
        it('should throw an error', async () => {
          const result = await checkExclusionList('ns4.epidc.co.kr', domainExclusionList);
          expect(result.length).toBe(1);
          expect(result[0]).toBe('domainExclusionList');
        });
      });

      describe('www.test.ambfinancial.com', () => {
        it('should throw an error', async () => {
          const result = await checkExclusionList('www.test.ambfinancial.com', domainExclusionList);
          expect(result.length).toBe(1);
          expect(result[0]).toBe('domainExclusionList');
        });
      });

      describe('test.domain.name.fr', () => {
        it('should do nothing', async () => {
          const result = await checkExclusionList('test.domain.name.fr', domainExclusionList);
          expect(result.length).toBe(0);
        });
      });
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
