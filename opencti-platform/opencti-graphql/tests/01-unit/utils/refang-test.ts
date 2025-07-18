import { describe, expect, it } from 'vitest';
import { refang } from '../../../src/utils/refang';

describe('refang tests', () => {
  it('should leave clean URLs unchanged', () => {
    const input = 'http://example.com/path?query=123';
    const output = refang(input);
    expect(output).toBe(input);
  });

  it('should refang common IOC patterns', () => {
    const input = 'Visit hxxp://evil[.]com/path?q=1';
    const output = refang(input);
    expect(output).toBe('Visit http://evil.com/path?q=1');
  });

  it('should restore multiple defanged elements in a string', () => {
    const input = 'Report from (at)example(dot)com and hxxps[:]//bad[.]site[:/]index';
    const output = refang(input);
    expect(output).toContain('http');
    expect(output).toContain('bad.site');
    expect(output).toContain('index');
    expect(output).toContain('@example.com');
  });

  it('should preserve surrounding words when refanging', () => {
    const input = 'indicator hxxp://test[.]com/data';
    const output = refang(input);
    expect(output).toMatch(/^indicator http:\/\/test\.com\/data$/);
  });

  it('should not throw on malformed URL with invalid percent encoding', () => {
    const malformed = 'check hxxp://evil[.]com/%E0%A4%A';
    const output = refang(malformed);
    expect(output).toContain('evil.com');
  });

  it('should strip trailing garbage characters from URLs', () => {
    const input = 'hxxp://site[.]com...';
    const output = refang(input);
    expect(output).toBe('http://site.com');
  });

  it('should handle mixed defanging styles in a single string', () => {
    const input = 'hxxp://example[.]com and hxxps://secure[.]site/path';
    const output = refang(input);
    expect(output).toBe('http://example.com and https://secure.site/path');
  });

  it('should return empty string when input is empty', () => {
    const input = '';
    const output = refang(input);
    expect(output).toBe('');
  });

  it('should return the original string if there is no defanging', () => {
    const input = 'Just a normal string without any defanging.';
    const output = refang(input);
    expect(output).toBe(input);
  });

  it('should refang URLs with query parameters', () => {
    const input = 'Check this hxxp://example[.]com/path?query=1&other=2';
    const output = refang(input);
    expect(output).toBe('Check this http://example.com/path?query=1&other=2');
  });

  it('should handle URLs with different defanging styles', () => {
    const input = 'Visit hxxps[:]//malicious(dot)site[.]com[:/]login';
    const output = refang(input);
    expect(output).toBe('Visit https://malicious.site.com/login');
  });

  it('should refang obfuscated email addresses', () => {
    const input = 'Contact us at contact(at)domain(dot)com for more info.';
    const output = refang(input);
    expect(output).toBe('Contact us at contact@domain.com for more info.');
  });

  it('should handle multiple mixed indicators in a sentence', () => {
    const input = 'For more info, visit hxxp://example[.]com or contact us at support(at)domain(dot)com.';
    const output = refang(input);
    expect(output).toBe('For more info, visit http://example.com or contact us at support@domain.com.');
  });

  it('should refang IP addresses with defanging', () => {
    const input = 'Connect to the server at 192[.]168[.]1[.]1 or hxxp://10[.]0[.]0[.]1/path';
    const output = refang(input);
    expect(output).toBe('Connect to the server at 192.168.1.1 or http://10.0.0.1/path');
  });

  it('should handle mixed protocols in URLs', () => {
    const input = 'Check both hxxp://example[.]com and hxxps://secure[.]site/path for updates.';
    const output = refang(input);
    expect(output).toBe('Check both http://example.com and https://secure.site/path for updates.');
  });

  it('should correctly refang domains with multiple subdomains', () => {
    const input = 'Access sub[.]domain[.]example[.]com for details';
    const output = refang(input);
    expect(output).toBe('Access sub.domain.example.com for details');
  });

  it('should refang URLs with unicode characters in the path', () => {
    const input = 'hxxps://example[.]com/p%C3%A1th';
    const output = refang(input);
    expect(output).toBe('https://example.com/p%C3%A1th');
  });

  it('should refang email addresses with unicode local part', () => {
    const input = 'Contact jöhn(at)domain(dot)com for support';
    const output = refang(input);
    expect(output).toBe('Contact jöhn@domain.com for support');
  });

  it('should refang defanged URLs surrounded by punctuation', () => {
    const input = 'See: (hxxp://test[.]com), or [hxxps://secure[.]site/path].';
    const output = refang(input);
    expect(output).toBe('See: (http://test.com), or [https://secure.site/path].');
  });

  it('should refang defanged email in the middle of a sentence with punctuation', () => {
    const input = 'Please email john(dot)doe(at)mail(dot)com, thanks!';
    const output = refang(input);
    expect(output).toBe('Please email john.doe@mail.com, thanks!');
  });
});
