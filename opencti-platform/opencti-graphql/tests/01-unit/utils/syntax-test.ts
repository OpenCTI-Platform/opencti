import { describe, expect, it } from 'vitest';
import {
  systemChecker,
  domainChecker,
  hostnameChecker,
  emailChecker,
  ipv6Checker,
  macAddrChecker,
  ipv4Checker,
  cpeChecker,
  cleanupIndicatorPattern,
} from '../../../src/utils/syntax';

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
    expect('mvix.온라인.한국').toMatch(domainChecker);
    expect('mvix.xn--oi2b61z32a.xn--3e0b707e').toMatch(domainChecker);
  });

  it('should not match a valid domain pattern', () => {
    expect('').not.toMatch(domainChecker);
    expect('erijgrjoprgjrejgoejrpojerbjrepobjreobjoperjboprejorpejgorpejeropgjreojgeprogjerpjgreojgoperjgpreojgoperjgorepjgporejgoprejgporejgorepjgoerpjgperjgpoerjgorejgporejoprejgopjergpjerogjrepjgerpgjergojrepgjrvenvrienvrepngvperjgprejgrpegjrepogjrepgjreogjerjgepjgrpejgrpejrgpjerpo.fr').not.toMatch(domainChecker);
  });

  it.skip('Domain-name regex parsing should be performant', async () => {
    const startDate = Date.now();
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
    // Valid IPv4 addresses
    expect('192.168.0.1').toMatch(ipv4Checker);
    expect('0.0.0.0').toMatch(ipv4Checker);
    expect('255.255.255.255').toMatch(ipv4Checker);
    expect('1.2.3.4').toMatch(ipv4Checker);
    expect('10.0.0.1').toMatch(ipv4Checker);
    expect('172.16.0.1').toMatch(ipv4Checker);
    expect('8.8.8.8').toMatch(ipv4Checker);

    // Valid IPv4 with CIDR notation
    expect('192.168.0.1/24').toMatch(ipv4Checker);
    expect('10.0.0.0/8').toMatch(ipv4Checker);
    expect('172.16.0.0/12').toMatch(ipv4Checker);
    expect('192.168.1.1/32').toMatch(ipv4Checker);
    expect('0.0.0.0/0').toMatch(ipv4Checker);

    // Invalid formats
    expect('invalid_ipv4').not.toMatch(ipv4Checker);
    expect('256.1.1.1').not.toMatch(ipv4Checker);
    expect('1.256.1.1').not.toMatch(ipv4Checker);
    expect('1.1.256.1').not.toMatch(ipv4Checker);
    expect('1.1.1.256').not.toMatch(ipv4Checker);
    expect('999.999.999.999').not.toMatch(ipv4Checker);
    expect('192.168.0').not.toMatch(ipv4Checker);
    expect('192.168.0.1.1').not.toMatch(ipv4Checker);

    // Invalid - Leading zeros (issue #12494)
    expect('01.1.1.1').not.toMatch(ipv4Checker);
    expect('1.01.1.1').not.toMatch(ipv4Checker);
    expect('1.1.01.1').not.toMatch(ipv4Checker);
    expect('1.1.1.01').not.toMatch(ipv4Checker);
    expect('001.1.1.1').not.toMatch(ipv4Checker);
    expect('192.168.001.1').not.toMatch(ipv4Checker);
    expect('010.010.010.010').not.toMatch(ipv4Checker);

    // Invalid CIDR
    expect('192.168.0.1/33').not.toMatch(ipv4Checker);
    expect('192.168.0.1/99').not.toMatch(ipv4Checker);
    expect('192.168.0.1/').not.toMatch(ipv4Checker);
  });

  it('should match a valid CPE pattern', () => {
    expect('cpe://example').toMatch(cpeChecker);
    expect('cpe:/a:example:ie').toMatch(cpeChecker);
    expect('cpe:/a:example:internet_explorer:8.0.6001:beta').toMatch(cpeChecker);
    expect('invalid_cpe').not.toMatch(cpeChecker);
  });
});

describe('cleanupIndicatorPattern - STIX pattern normalization', () => {
  // --- Property name quoting normalization ---

  it('should normalize quoted MD5 property name to unquoted form to avoid duplicates', () => {
    const patternWithQuotedKey = "[file:hashes.'MD5' = 'e1d9c90de2568f34ad689c71dac09c62']";
    const patternWithUnquotedKey = "[file:hashes.MD5 = 'e1d9c90de2568f34ad689c71dac09c62']";

    const normalizedWithQuotes = cleanupIndicatorPattern('stix', patternWithQuotedKey);
    const normalizedWithoutQuotes = cleanupIndicatorPattern('stix', patternWithUnquotedKey);

    expect(normalizedWithQuotes).toBe(normalizedWithoutQuotes);
  });

  it('should normalize quoted property names that are valid identifiers (letters, digits, underscore)', () => {
    const patternWithQuotedKey = "[file:hashes.'MD5' = 'abc123']";
    const normalizedPattern = cleanupIndicatorPattern('stix', patternWithQuotedKey);

    expect(normalizedPattern).toContain('.MD5');
    expect(normalizedPattern).not.toContain(".'MD5'");
  });

  it('should keep quotes on property names that require them (containing hyphens like SHA-256)', () => {
    const patternWithSHA256 = "[file:hashes.'SHA-256' = 'a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1']";
    const normalized = cleanupIndicatorPattern('stix', patternWithSHA256);

    expect(normalized).toContain(".'SHA-256'");
  });

  it('should produce the same normalized pattern regardless of property name quoting for multiple hash types', () => {
    const patternA = "[file:hashes.'MD5' = 'e1d9c90de2568f34ad689c71dac09c62'] AND [file:hashes.'SHA-256' = 'abc']";
    const patternB = "[file:hashes.MD5 = 'e1d9c90de2568f34ad689c71dac09c62'] AND [file:hashes.'SHA-256' = 'abc']";

    const normalizedA = cleanupIndicatorPattern('stix', patternA);
    const normalizedB = cleanupIndicatorPattern('stix', patternB);

    expect(normalizedA).toBe(normalizedB);
  });

  // --- Non-STIX pattern types ---

  it('should not alter non-STIX pattern types', () => {
    const yaraPattern = 'rule test { strings: $a = /md5/ condition: $a }';
    expect(cleanupIndicatorPattern('yara', yaraPattern)).toBe(yaraPattern);
    expect(cleanupIndicatorPattern('pcre', yaraPattern)).toBe(yaraPattern);
  });

  it('should handle patternType case-insensitivity (STIX, Stix, stix)', () => {
    const pattern = "[file:hashes.'MD5' = 'abc123']";
    const normalizedLower = cleanupIndicatorPattern('stix', pattern);
    const normalizedUpper = cleanupIndicatorPattern('STIX', pattern);
    const normalizedMixed = cleanupIndicatorPattern('Stix', pattern);

    expect(normalizedLower).toBe(normalizedUpper);
    expect(normalizedLower).toBe(normalizedMixed);
  });

  // --- Value preservation ---

  it('should not strip quotes from string literal values (after = operator)', () => {
    const pattern = "[file:hashes.MD5 = 'e1d9c90de2568f34ad689c71dac09c62']";
    const normalized = cleanupIndicatorPattern('stix', pattern);

    expect(normalized).toContain("'e1d9c90de2568f34ad689c71dac09c62'");
  });

  // --- Edge cases & robustness ---

  it('should return pattern unchanged when pattern is null or empty for STIX type', () => {
    expect(cleanupIndicatorPattern('stix', null)).toBeNull();
    expect(cleanupIndicatorPattern('stix', undefined)).toBeUndefined();
    expect(cleanupIndicatorPattern('stix', '')).toBe('');
  });

  it('should be idempotent - normalizing an already normalized pattern should return the same result', () => {
    const pattern = "[file:hashes.'MD5' = 'e1d9c90de2568f34ad689c71dac09c62']";
    const firstPass = cleanupIndicatorPattern('stix', pattern);
    const secondPass = cleanupIndicatorPattern('stix', firstPass);

    expect(firstPass).toBe(secondPass);
  });

  it('should normalize whitespace around operators and keywords', () => {
    const messyPattern = "[ipv4-addr:value   =   '198.51.100.1/32']";
    const normalized = cleanupIndicatorPattern('stix', messyPattern);

    expect(normalized).toBe("[ipv4-addr:value = '198.51.100.1/32']");
  });

  it('should trim leading and trailing whitespace from the pattern', () => {
    const pattern = "   [ipv4-addr:value = '1.2.3.4']   ";
    const normalized = cleanupIndicatorPattern('stix', pattern);

    expect(normalized).toBe("[ipv4-addr:value = '1.2.3.4']");
  });

  it('should handle windows-pebinary-ext quoted extension name (contains hyphens)', () => {
    const pattern = "[file:extensions.'windows-pebinary-ext'.sections[*].entropy > 7.0]";
    const normalized = cleanupIndicatorPattern('stix', pattern);

    // 'windows-pebinary-ext' must stay quoted (contains hyphens)
    expect(normalized).toContain(".'windows-pebinary-ext'");
  });
});
