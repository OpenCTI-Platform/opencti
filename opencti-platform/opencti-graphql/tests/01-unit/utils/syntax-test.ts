import { describe, expect, it } from 'vitest';
import { systemChecker, domainChecker, hostnameChecker, emailChecker, ipv6Checker, macAddrChecker, ipv4Checker, cpeChecker } from '../../../src/utils/syntax';

describe('Regex Pattern Tests', () => {
  it('should match a valid system pattern', () => {
    expect('1234567890').toMatch(systemChecker);
    expect('123').toMatch(systemChecker);
    expect('').toMatch(systemChecker);
  });

  it('should match a valid domain pattern', () => {
    expect('example.com').toMatch(domainChecker);
    expect('sub.example.co.uk').toMatch(domainChecker);
    expect('løveskateboards.com').toMatch(domainChecker);
    expect('test._mysubdomain.mydomain.com').toMatch(domainChecker);
    expect('test_mysubdomain.domain.io').toMatch(domainChecker);
    expect('test-test.com').toMatch(domainChecker);
    expect('test-test.mytest.com').toMatch(domainChecker);
    expect('observableTestPromote.com').toMatch(domainChecker);
  });

  it('should not match a valid domain pattern', () => {
    expect('').not.toMatch(domainChecker);
    expect('erijgrjoprgjrejgoejrpojerbjrepobjreobjoperjboprejorpejgorpejeropgjreojgeprogjerpjgreojgoperjgpreojgoperjgorepjgporejgoprejgporejgorepjgoerpjgperjgpoerjgorejgporejoprejgopjergpjerogjrepjgerpgjergojrepgjrvenvrienvrepngvperjgprejgrpegjrepogjrepgjreogjerjgepjgrpejgrpejrgpjerpo.fr').not.toMatch(domainChecker);
  });

  it('Domain-name regex parsing should be perfomant', async () => {
    const startDate = Date.now();
    // eslint-disable-next-line no-plusplus
    for (let i = 0; i < 1000; i++) {
      domainChecker.test('test._mysubdomain.mydomain.com');
      domainChecker.test('invalid_domain.12_3');
    }
    expect(Date.now() - startDate, 'Domain-name regex parsing should be performant').toBeLessThanOrEqual(2);
  });

  it('should match a valid hostname pattern', () => {
    expect('my-host').toMatch(hostnameChecker);
    expect('my_host').toMatch(hostnameChecker);
    expect('invalid-host_').not.toMatch(hostnameChecker);
  });

  it('should match a valid email pattern', () => {
    expect('test@example.com').toMatch(emailChecker);
    expect('mastodon+ada.lovelace@mymail.org').toMatch(emailChecker);
    expect('invalid_email').not.toMatch(emailChecker);
  });

  it('should match a valid IPv6 pattern', () => {
    expect('2001:0db8:85a3:0000:0000:8a2e:0370:7334').toMatch(ipv6Checker);
    expect('invalid_ipv6').not.toMatch(ipv6Checker);
  });

  it('should match a valid MAC address pattern', () => {
    expect('00:1A:2B:3C:4D:5E').toMatch(macAddrChecker);
    expect('invalid_mac').not.toMatch(macAddrChecker);
  });

  it('should match a valid IPv4 pattern', () => {
    expect('192.168.0.1').toMatch(ipv4Checker);
    expect('invalid_ipv4').not.toMatch(ipv4Checker);
  });

  it('should match a valid CPE pattern', () => {
    expect('cpe://example').toMatch(cpeChecker);
    expect('cpe:/a:example:ie').toMatch(cpeChecker);
    expect('cpe:/a:example:internet_explorer:8.0.6001:beta').toMatch(cpeChecker);
    expect('invalid_cpe').not.toMatch(cpeChecker);
  });
});
