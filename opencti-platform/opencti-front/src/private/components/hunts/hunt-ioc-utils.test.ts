import { describe, expect, it } from 'vitest';
import { detectIoc, iocTypeLabel, iocValuesToText, parseIocText, refangIoc } from './hunt-ioc-utils';

describe('Indicator hunt pasted values', () => {
  it('should restore defanged values', () => {
    expect(refangIoc('hxxps://evil[.]example[.]com/a')).toBe('https://evil.example.com/a');
    expect(refangIoc('198(.)51(.)100(.)7')).toBe('198.51.100.7');
    expect(refangIoc('phisher[@]evil.example.com')).toBe('phisher@evil.example.com');
  });

  it('should type each value as the platform does', () => {
    expect(detectIoc('198.51.100.7')).toEqual({ observable_type: 'IPv4-Addr', value: '198.51.100.7' });
    expect(detectIoc('2001:DB8::1')).toEqual({ observable_type: 'IPv6-Addr', value: '2001:db8::1' });
    expect(detectIoc('https://evil.example.com/Payload')).toEqual({ observable_type: 'Url', value: 'https://evil.example.com/Payload' });
    expect(detectIoc('Phisher@Evil.example.com')).toEqual({ observable_type: 'Email-Addr', value: 'phisher@evil.example.com' });
    expect(detectIoc('00-1A-2B-3C-4D-5E')).toEqual({ observable_type: 'Mac-Addr', value: '00:1a:2b:3c:4d:5e' });
    expect(detectIoc('D41D8CD98F00B204E9800998ECF8427E')).toEqual({ observable_type: 'StixFile', value: 'd41d8cd98f00b204e9800998ecf8427e' });
    expect(detectIoc('Evil.Example.com.')).toEqual({ observable_type: 'Domain-Name', value: 'evil.example.com' });
    expect(detectIoc('198.51.100.300')).toBeNull();
    expect(detectIoc('deadbeef')).toBeNull();
    expect(detectIoc('not-a-value')).toBeNull();
  });

  it('should split a pasted list, flag what is not a value and count duplicates', () => {
    const parsed = parseIocText('198.51.100.7, evil[.]example.com\n198.51.100.7;\tnot-a-value\n\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ');
    expect(parsed.values).toEqual([
      { observable_type: 'IPv4-Addr', value: '198.51.100.7' },
      { observable_type: 'Domain-Name', value: 'evil.example.com' },
      { observable_type: 'StixFile', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    ]);
    expect(parsed.invalid).toEqual(['not-a-value']);
    expect(parsed.duplicates).toBe(1);
    expect(parseIocText('')).toEqual({ values: [], invalid: [], duplicates: 0 });
    expect(iocValuesToText(parsed.values.slice(0, 2))).toBe('198.51.100.7\nevil.example.com');
  });

  it('should label observable types', () => {
    const t = (message: string, options?: { values: Record<string, string> }) => message.replace('{algorithm}', options?.values.algorithm ?? '');
    expect(iocTypeLabel('IPv4-Addr', t)).toBe('IPv4 address');
    expect(iocTypeLabel('StixFile', t, 'SHA-256')).toBe('File hash (SHA-256)');
    expect(iocTypeLabel('Software', t)).toBe('Software');
  });
});
