import { describe, expect, it } from 'vitest';
import { findKeyword, isTypeMatching } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-engine';

describe('Intelligence requirement engine: keywords', () => {
  const report = { name: 'Weekly FortiOS exploitation', description: 'Ransomware operators abuse an SSL-VPN flaw', x_opencti_aliases: ['PHPShell campaign'] };

  it('should find a keyword in the name, case-insensitive', () => {
    expect(findKeyword(report, ['fortios'], ['name', 'description', 'content'])).toEqual({ keyword: 'fortios', field: 'name' });
  });

  it('should find a keyword in the description', () => {
    expect(findKeyword(report, ['ssl-vpn'], ['name', 'description'])).toEqual({ keyword: 'ssl-vpn', field: 'description' });
  });

  it('should search aliases as part of the name', () => {
    expect(findKeyword(report, ['phpshell'], ['name'])).toEqual({ keyword: 'phpshell', field: 'name' });
  });

  it('should only search the selected fields', () => {
    expect(findKeyword(report, ['ssl-vpn'], ['name'])).toBeNull();
  });

  it('should return null when nothing matches', () => {
    expect(findKeyword(report, ['ivanti'], ['name', 'description', 'content'])).toBeNull();
  });
});

describe('Intelligence requirement engine: types', () => {
  it('should accept any type when no target type is set', () => {
    expect(isTypeMatching('Malware', [])).toBe(true);
  });
  it('should match the exact type', () => {
    expect(isTypeMatching('Vulnerability', ['Vulnerability'])).toBe(true);
    expect(isTypeMatching('Malware', ['Vulnerability'])).toBe(false);
  });
  it('should match a parent type', () => {
    expect(isTypeMatching('Malware', ['Stix-Domain-Object'])).toBe(true);
  });
});
