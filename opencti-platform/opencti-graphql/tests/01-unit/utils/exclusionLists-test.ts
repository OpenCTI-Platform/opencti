import { describe, expect, it } from 'vitest';
import { checkIpAddrType, convertIpAddr, convertIpv4ToBinary, convertIpv6ToBinary, checkExclusionLists } from '../../../src/utils/exclusionLists';
import { ENTITY_DOMAIN_NAME, ENTITY_IPV4_ADDR, ENTITY_IPV6_ADDR, ENTITY_URL } from '../../../src/schema/stixCyberObservable';

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
const ipListv4Result = [
  '11000011111110100100101110110010',
  '01001000000100110001010000001100',
  '01010101000011111011000011110011',
  '000000010111010',
  '011001010100111111100001',
  '110101011010011001010010',
];
const ipListv6Result = [
  '00100000000000010001010010001111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000001',
  '00100110000000101111101110100001000010100000000000000000000000000000000000000000000000000000000000000001000000000000000000000001',
  '00101010000011001000111111000001011001000100000100000000000000000000000000000000000000000000000000000100000100101010101100110100',
  '001000000000000100010100001001000000000000000000',
  '00100110000000001001000000000000000100000011011',
  '00101010000000100000000011101000',
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
  values: ipv4ListResult.sort(),
  ranges: [32, 22, 20, 19]
}];
const ipv6ExclusionList = [{
  id: 'ipv6ListResult',
  types: [ENTITY_IPV6_ADDR],
  values: ipv6ListResult.sort(),
  ranges: [128, 48, 33, 32]
}];
const domainExclusionList = [{
  id: 'domainExclusionList',
  types: [ENTITY_DOMAIN_NAME, ENTITY_URL],
  values: domainNameList.sort()
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
    describe('When I have a list of Ipv4', () => {
      it('should return a converted array of binary', () => {
        const result = convertIpAddr(ipv4ListToTest);
        expect(result.ipv4.values.sort().join('')).toBe(ipv4ListResult.sort().join(''));
      });
    });

    describe('When I have a list of Ipv6', () => {
      it('should return a converted array of binary', () => {
        const result = convertIpAddr(ipv6ListToTest);
        expect(result.ipv6.values.sort().join('')).toBe(ipv6ListResult.sort().join(''));
      });
    });

    describe('When I have a list of Ipv4 and IPV6', () => {
      it('should return a converted array of binary', () => {
        const result = convertIpAddr(ipListToTest);
        expect(result.ipv4.values.sort().join('')).toBe(ipListv4Result.sort().join(''));
        expect(result.ipv6.values.sort().join('')).toBe(ipListv6Result.sort().join(''));
      });
    });
  });

  describe('checkIpAddressLists', () => {
    describe('When I check if an IPV4 is contained on lists', () => {
      describe('99.99.99.193', () => {
        it('should throw an error', async () => {
          const result = checkExclusionLists('99.99.99.193', ENTITY_IPV4_ADDR, ipv4ExclusionList);
          expect(result).not.toBe(null);
          expect(result?.value).toBe('99.99.99.193');
          expect(result?.listId).toBe('ipv4ListResult');
        });
      });

      describe('99.87.23.11', () => {
        it('should throw an error', async () => {
          const result = checkExclusionLists('99.87.23.11', ENTITY_IPV4_ADDR, ipv4ExclusionList);
          expect(result).not.toBe(null);
          expect(result?.value).toBe('99.87.23.11');
          expect(result?.listId).toBe('ipv4ListResult');
        });
      });

      describe('22.22.22.22', () => {
        it('should do nothing', async () => {
          const result = checkExclusionLists('22.22.22.22', ENTITY_IPV4_ADDR, ipv4ExclusionList);
          expect(result).toBe(null);
        });
      });
    });

    describe('When I check if an IPV6 is contained on lists', () => {
      describe('2a12:e342:200::2:1819', () => {
        it('should throw an error', async () => {
          const result = checkExclusionLists('2a12:e342:200::2:1819', ENTITY_IPV6_ADDR, ipv6ExclusionList);
          expect(result).not.toBe(null);
          expect(result?.value).toBe('2a12:e342:200::2:1819');
          expect(result?.listId).toBe('ipv6ListResult');
        });
      });

      describe('2602:fba1:a00::100:19', () => {
        it('should do nothing', async () => {
          const result = checkExclusionLists('2602:fba1:a00::100:19', ENTITY_DOMAIN_NAME, ipv6ExclusionList);
          expect(result).toBe(null);
        });
      });
    });
  });

  describe('checkExclusionList', () => {
    describe('When I check if a domain name is contained on lists', () => {
      describe('ns4.epidc.co.kr', () => {
        it('should throw an error', async () => {
          const result = checkExclusionLists('ns4.epidc.co.kr', ENTITY_DOMAIN_NAME, domainExclusionList);
          expect(result).not.toBe(null);
          expect(result?.value).toBe('ns4.epidc.co.kr');
          expect(result?.listId).toBe('domainExclusionList');
        });
      });

      describe('www.test.ambfinancial.com', () => {
        it('should throw an error', async () => {
          const result = checkExclusionLists('www.test.ambfinancial.com', ENTITY_DOMAIN_NAME, domainExclusionList);
          expect(result).not.toBe(null);
          expect(result?.value).toBe('.ambfinancial.com');
          expect(result?.listId).toBe('domainExclusionList');
        });
      });

      describe('test.domain.name.fr', () => {
        it('should do nothing', async () => {
          const result = checkExclusionLists('test.domain.name.fr', ENTITY_DOMAIN_NAME, domainExclusionList);
          expect(result).toBe(null);
        });
      });
    });
  });
});
