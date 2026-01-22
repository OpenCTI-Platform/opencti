import { describe, expect, it } from 'vitest';
import { computeStreamRemoteUrl } from '../../../src/domain/connector';
import { FunctionalError } from '../../../src/config/errors';

describe('connector stream test', () => {
  it.each([
    {uri: 'https://myremoteocti.com/path', isHttps: true},
    {uri: 'https://myremoteocti.com/path?magic=number', isHttps: true},
    {uri: 'https://myremoteocti.com/path#magic', isHttps: true},
    {uri: 'https://myremoteocti.com/path/', isHttps: true},
    {uri: 'https://myremoteocti.com/path', isHttps: true},
    {uri: 'http://myremoteocti.com/path', isHttps: false},
    {uri: 'http://myremoteocti.com/path?magic=number', isHttps: false},
    {uri: 'http://myremoteocti.com/path/', isHttps: false},
  ])('should use only base URL to query remote stream', (inputUri: {uri: string, isHttps: boolean }) => {
    const result = computeStreamRemoteUrl(inputUri.uri);
    expect(result).toBe(`http${inputUri.isHttps ?'s':''}://myremoteocti.com/path/graphql`);
  });

  it('should localhost be ok', async () => {
    const resultLocalhost1 = computeStreamRemoteUrl('http://localhost:4500');
    expect(resultLocalhost1).toBe('http://localhost:4500/graphql');

    const resultLocalhost2 = computeStreamRemoteUrl('http://127.0.0.1:4500');
    expect(resultLocalhost2).toBe('http://127.0.0.1:4500/graphql');
  });

  it('should non http protocol be refused', () => {
    expect(() => {
      computeStreamRemoteUrl('ftp://localhost:4500');
    }).toThrowError(FunctionalError('Stream URL format is not correct'));
  });
});
