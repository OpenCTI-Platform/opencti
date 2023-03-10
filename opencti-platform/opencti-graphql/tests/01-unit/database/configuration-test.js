import { describe, expect, it } from 'vitest';
import { getPlatformHttpProxyAgent, isUriProxyExcluded } from '../../../src/config/conf';

describe('configuration testing', () => {
  it('should proxy uri correctly excluded simple', () => {
    expect(isUriProxyExcluded('www.test.example.com', ['www.test.example.com'])).toBe(true);
    expect(isUriProxyExcluded('example.com', ['example.com'])).toBe(true);
    expect(isUriProxyExcluded('example.com', ['example.co'])).toBe(false);
  });
  it('should proxy uri correctly excluded for regexp', () => {
    expect(isUriProxyExcluded('www.test.example.com', ['*.test.example.com'])).toBe(true);
    expect(isUriProxyExcluded('www.test.example.com', ['*.test.ex*le.com'])).toBe(true);
  });
  it('should proxy uri correctly excluded for ip addresses', () => {
    expect(isUriProxyExcluded('127.0.0.1', ['127.0.0.1'])).toBe(true);
    expect(isUriProxyExcluded('127.0.0.1', ['127.0.0.2'])).toBe(false);
    expect(isUriProxyExcluded('127.0.0.1', ['127.0.0.1'])).toBe(true);
    expect(isUriProxyExcluded('127.0.0.12', ['127.0.0.1'])).toBe(false);
    expect(isUriProxyExcluded('172.0.0.12', ['172.0.0.0/24'])).toBe(true);
  });
  it('should proxy configured correctly', () => {
    // https
    const httpsAgent = getPlatformHttpProxyAgent('https://192.168.101.12:3000');
    expect(httpsAgent.secureProxy).toBe(true);
    expect(httpsAgent.proxy).toBeDefined();
    expect(httpsAgent.proxy.host).toBe('proxy.opencti.io');
    expect(httpsAgent.proxy.port).toBe(2100);
    // http
    const httpAgent = getPlatformHttpProxyAgent('http://192.168.101.12:3000');
    expect(httpAgent.secureProxy).toBe(false);
    expect(httpAgent.proxy).toBeDefined();
    expect(httpAgent.proxy.host).toBe('proxy.opencti.io');
    expect(httpAgent.proxy.port).toBe(2000);
    // Test excluded uri
    const excluded = getPlatformHttpProxyAgent('https://localhost:3000');
    expect(excluded).toBeUndefined();
  });
});
