import { describe, it, expect } from 'vitest';
import { getProxyConfigurationForContract, injectProxyConfiguration } from '../../../src/config/proxy-config';
import type { ConfigAdapter } from '../../../src/config/proxy-config';

// Helper function to create mock certificate content
const createMockCert = (identifier: string): string => {
  return `-----BEGIN CERTIFICATE-----\nMOCKED_CONTENT_FOR_${identifier}\n-----END CERTIFICATE-----`;
};

// Test configuration adapter factory function
const createTestConfigAdapter = (config: Record<string, any>): ConfigAdapter => ({
  get: (key: string) => config[key],

  booleanConf: (key: string, defaultValue: boolean) => {
    const value = config[key];
    if (value === undefined) return defaultValue;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      return value === '1' || value.toLowerCase() === 'true';
    }
    return defaultValue;
  },

  loadCert: (cert: string | undefined) => {
    if (!cert) return undefined;

    // If it's already inline certificate content, return it as-is (like real loadCert does)
    if (cert.startsWith('-----BEGIN')) {
      return cert;
    }

    // Mock certificate loading - simulate file not found for certain paths
    if (cert === '/not/found.pem' || cert === '/invalid/cert.pem') {
      return undefined; // Simulate file not found
    }

    // Mock certificate loading from file path - in tests, return a mock certificate content
    return createMockCert(cert);
  }
});

describe('Connector Proxy configuration tests', () => {
  describe('getProxyConfigurationForContract', () => {
    it('should return proxy configuration with all settings', () => {
      const configAdapter = createTestConfigAdapter({
        http_proxy: 'http://proxy.example.com:8080',
        https_proxy: 'https://secure-proxy.example.com:8443',
        no_proxy: 'localhost,127.0.0.1,.internal.domain',
        https_proxy_ca: ['/path/to/ca-cert.pem'],
        https_proxy_reject_unauthorized: true
      });

      const result = getProxyConfigurationForContract(configAdapter);

      expect(result).toBeDefined();
      expect(result.HTTP_PROXY).toBe('http://proxy.example.com:8080');
      expect(result.HTTPS_PROXY).toBe('https://secure-proxy.example.com:8443');
      expect(result.NO_PROXY).toBe('localhost,127.0.0.1,.internal.domain');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('-----BEGIN CERTIFICATE-----');
      expect(result.HTTPS_PROXY_REJECT_UNAUTHORIZED).toBe('true');
    });

    it('should return empty proxy configuration when no proxy is set', () => {
      const configAdapter = createTestConfigAdapter({
        http_proxy: '',
        https_proxy: '',
        no_proxy: '',
        https_proxy_ca: [],
        https_proxy_reject_unauthorized: undefined
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Empty proxy values should not be included (except reject_unauthorized which has default)
      expect(result).toEqual({
        HTTPS_PROXY_REJECT_UNAUTHORIZED: 'true'
      });
    });

    it('should handle credentials in proxy URLs correctly', () => {
      const configAdapter = createTestConfigAdapter({
        http_proxy: 'http://username:password@proxy.example.com:8080',
        https_proxy: 'https://user:pass@secure-proxy.example.com:8443',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Should preserve credentials in the URL
      expect(result.HTTP_PROXY).toBe('http://username:password@proxy.example.com:8080');
      expect(result.HTTPS_PROXY).toBe('https://user:pass@secure-proxy.example.com:8443');
    });

    it('should validate and filter NO_PROXY entries for urllib.request compatibility', () => {
      const configAdapter = createTestConfigAdapter({
        no_proxy: 'localhost,127.0.0.1,192.168.1.0/24,*.internal.com,.example.org,specific.domain.com',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // urllib.request compatible formats should be kept
      const noProxyList = result.NO_PROXY.split(',');
      expect(noProxyList).toContain('localhost');
      expect(noProxyList).toContain('127.0.0.1');
      expect(noProxyList).toContain('.example.org');
      expect(noProxyList).toContain('specific.domain.com');

      // Incompatible formats should be filtered out
      expect(noProxyList).not.toContain('192.168.1.0/24'); // CIDR not supported
      expect(noProxyList).not.toContain('*.internal.com'); // Wildcard * not supported
    });

    it('should keep valid urllib.request NO_PROXY formats', () => {
      const configAdapter = createTestConfigAdapter({
        no_proxy: 'localhost,127.0.0.1:8080,.example.com,api.example.com,10.0.0.1',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // All these are valid urllib.request formats
      expect(result.NO_PROXY).toBe('localhost,127.0.0.1:8080,.example.com,api.example.com,10.0.0.1');
      const noProxyList = result.NO_PROXY.split(',');
      expect(noProxyList).toContain('localhost');
      expect(noProxyList).toContain('127.0.0.1:8080'); // IP with port
      expect(noProxyList).toContain('.example.com'); // Leading dot
      expect(noProxyList).toContain('api.example.com'); // Hostname
      expect(noProxyList).toContain('10.0.0.1'); // IP
      expect(noProxyList).toHaveLength(5);
    });

    it('should filter out urllib.request incompatible NO_PROXY formats', () => {
      const configAdapter = createTestConfigAdapter({
        no_proxy: '*.example.com,192.168.0.0/16,10.0.0.0/8,*,*.*.example.com',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // All entries should be filtered out as they use wildcards or CIDR
      // Empty NO_PROXY should not be included in config
      expect(result.NO_PROXY).toBe(undefined);
    });

    it('should handle CA certificates from configuration', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/ca-cert.pem', '/path/to/ssl-cert.pem', '/path/to/ca-bundle.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Now we expect concatenated certificate content
      const certificates = result.HTTPS_CA_CERTIFICATES.split('\n-----BEGIN CERTIFICATE-----');
      expect(certificates).toHaveLength(3);
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/ca-cert.pem');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/ssl-cert.pem');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/ca-bundle.pem');
    });

    it('should handle inline certificate content (not file path)', () => {
      const inlineCert1 = createMockCert('INLINE_CERT_1');
      const inlineCert2 = createMockCert('INLINE_CERT_2');

      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: [inlineCert1, inlineCert2],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Inline certificates should be returned as-is, not re-mocked
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_INLINE_CERT_1');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_INLINE_CERT_2');
      expect(result.HTTPS_CA_CERTIFICATES).toBe(`${inlineCert1}\n${inlineCert2}`);
    });

    it('should handle mixed inline and file path certificates', () => {
      const inlineCert = createMockCert('INLINE_CERT');

      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/file-cert.pem', inlineCert, '/path/to/another-cert.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Should contain both mocked file content and inline content
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/file-cert.pem');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_INLINE_CERT');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/another-cert.pem');

      // All three certificates should be present
      const certificateCount = (result.HTTPS_CA_CERTIFICATES.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
      expect(certificateCount).toBe(3);
    });

    it('should handle https_proxy_reject_unauthorized setting', () => {
      // Test with rejection disabled
      const configAdapter1 = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_reject_unauthorized: '0',
        http_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      let result = getProxyConfigurationForContract(configAdapter1);
      expect(result.HTTPS_PROXY_REJECT_UNAUTHORIZED).toBe('false');

      // Test with rejection enabled
      const configAdapter2 = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_reject_unauthorized: '1',
        http_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      result = getProxyConfigurationForContract(configAdapter2);
      expect(result.HTTPS_PROXY_REJECT_UNAUTHORIZED).toBe('true');

      // Test with undefined (default to false for proxy)
      const configAdapter3 = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_reject_unauthorized: undefined,
        http_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      result = getProxyConfigurationForContract(configAdapter3);
      expect(result.HTTPS_PROXY_REJECT_UNAUTHORIZED).toBe('true');
    });

    it('should handle whitespace in NO_PROXY correctly', () => {
      const configAdapter = createTestConfigAdapter({
        no_proxy: ' localhost , 127.0.0.1 , .internal.com ',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Should trim whitespace
      expect(result.NO_PROXY).toBe('localhost,127.0.0.1,.internal.com');
      const noProxyList = result.NO_PROXY.split(',');
      expect(noProxyList).toContain('localhost');
      expect(noProxyList).toContain('127.0.0.1');
      expect(noProxyList).toContain('.internal.com');
      expect(noProxyList).toHaveLength(3);
    });

    it('should handle CA certificates as a single string', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: '/path/to/single-cert.pem',
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // String value should be rejected as per new validation
      expect(result.HTTPS_CA_CERTIFICATES).toBe(undefined);
    });

    it('should filter out empty CA certificate entries', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/cert1.pem', '', null, '/path/to/cert2.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Now we expect concatenated certificate content
      const certificates = result.HTTPS_CA_CERTIFICATES.split('\n-----BEGIN CERTIFICATE-----');
      expect(certificates).toHaveLength(2);
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/cert1.pem');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/cert2.pem');
    });

    // Edge case tests for new validations
    it('should handle invalid proxy URLs gracefully', () => {
      const configAdapter = createTestConfigAdapter({
        http_proxy: 'invalid-url-without-protocol',
        https_proxy: 'ftp://unsupported-protocol.com:8080',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Invalid URLs should result in empty proxy configuration
      expect(result.HTTP_PROXY).toBe(undefined);
      expect(result.HTTPS_PROXY).toBe(undefined);
    });

    it('should handle https_proxy_ca as non-array type (string) with error', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: 'this-should-be-an-array',
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // String value should be rejected, resulting in no CA certificates
      expect(result.HTTPS_CA_CERTIFICATES).toBe(undefined);
    });

    it('should handle https_proxy_ca as number type with error', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: 12345,
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Number value should be rejected, resulting in no CA certificates
      expect(result.HTTPS_CA_CERTIFICATES).toBe(undefined);
    });

    it('should handle empty array for https_proxy_ca', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: [],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Empty array should result in no CA certificates key
      expect(result.HTTPS_CA_CERTIFICATES).toBe(undefined);
    });

    it('should handle non-string elements in https_proxy_ca array', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/cert1.pem', 123, { invalid: 'object' }, '/path/to/cert2.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Only valid string paths should be processed
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/cert1.pem');
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/cert2.pem');
      expect(result.HTTPS_CA_CERTIFICATES).not.toContain('123');
      expect(result.HTTPS_CA_CERTIFICATES).not.toContain('object');
    });

    it('should handle certificates that fail to load', () => {
      const configAdapter = createTestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/valid.pem', '/not/found.pem', '/invalid/cert.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Only successfully loaded certificates should be included
      expect(result.HTTPS_CA_CERTIFICATES).toContain('MOCKED_CONTENT_FOR_/path/to/valid.pem');
      expect(result.HTTPS_CA_CERTIFICATES).not.toContain('MOCKED_CONTENT_FOR_/not/found.pem');
      expect(result.HTTPS_CA_CERTIFICATES).not.toContain('MOCKED_CONTENT_FOR_/invalid/cert.pem');
    });

    it('should deduplicate NO_PROXY entries', () => {
      const configAdapter = createTestConfigAdapter({
        no_proxy: 'localhost,localhost,127.0.0.1,localhost,.example.com,.example.com',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Duplicates should be removed
      const noProxyList = result.NO_PROXY.split(',');
      expect(noProxyList.filter((item) => item === 'localhost')).toHaveLength(1);
      expect(noProxyList.filter((item) => item === '127.0.0.1')).toHaveLength(1);
      expect(noProxyList.filter((item) => item === '.example.com')).toHaveLength(1);
      expect(noProxyList).toHaveLength(3);
    });

    it('should not include empty proxy values in config', () => {
      const configAdapter = createTestConfigAdapter({
        http_proxy: '',
        https_proxy: '',
        no_proxy: '',
        https_proxy_ca: [],
        https_proxy_reject_unauthorized: true
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Empty proxy values should not be included (except reject_unauthorized which has default)
      expect(result.HTTP_PROXY).toBe(undefined);
      expect(result.HTTPS_PROXY).toBe(undefined);
      expect(result.NO_PROXY).toBe(undefined);
      expect(result.HTTPS_CA_CERTIFICATES).toBe(undefined);
      // Only reject_unauthorized should be present
      expect(result.HTTPS_PROXY_REJECT_UNAUTHORIZED).toBe('true');
    });

    it('should validate SOCKS proxy URLs', () => {
      const configAdapter = createTestConfigAdapter({
        http_proxy: 'socks5://proxy.example.com:1080',
        https_proxy: 'socks4://proxy.example.com:1080',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // SOCKS proxies should be valid
      expect(result.HTTP_PROXY).toBe('socks5://proxy.example.com:1080');
      expect(result.HTTPS_PROXY).toBe('socks4://proxy.example.com:1080');
    });

    it('should handle NO_PROXY with only whitespace', () => {
      const configAdapter = createTestConfigAdapter({
        no_proxy: '   ,  ,   ',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = getProxyConfigurationForContract(configAdapter);

      // Only whitespace should result in empty NO_PROXY
      expect(result.NO_PROXY).toBe(undefined);
    });
  });

  describe('injectProxyConfiguration', () => {
    it('should inject proxy configuration into existing contract configuration', () => {
      const existingConfig = [
        { key: 'IPINFO_TOKEN', value: 'test-token' },
        { key: 'CONNECTOR_AUTO', value: 'true' }
      ];

      const configAdapter = createTestConfigAdapter({
        http_proxy: 'http://proxy.example.com:8080',
        https_proxy: 'https://secure-proxy.example.com:8443',
        no_proxy: 'localhost,127.0.0.1',
        https_proxy_ca: [],
        https_proxy_reject_unauthorized: true
      });

      const result = injectProxyConfiguration(existingConfig, configAdapter);

      // Original config should be preserved
      expect(result.find((item) => item.key === 'IPINFO_TOKEN')).toEqual({ key: 'IPINFO_TOKEN', value: 'test-token' });
      expect(result.find((item) => item.key === 'CONNECTOR_AUTO')).toEqual({ key: 'CONNECTOR_AUTO', value: 'true' });

      // Proxy config should be added
      expect(result.find((item) => item.key === 'HTTP_PROXY')).toEqual({ key: 'HTTP_PROXY', value: 'http://proxy.example.com:8080' });
      expect(result.find((item) => item.key === 'HTTPS_PROXY')).toEqual({ key: 'HTTPS_PROXY', value: 'https://secure-proxy.example.com:8443' });
      expect(result.find((item) => item.key === 'NO_PROXY')).toEqual({ key: 'NO_PROXY', value: 'localhost,127.0.0.1' });
      expect(result.find((item) => item.key === 'HTTPS_PROXY_REJECT_UNAUTHORIZED')).toEqual({ key: 'HTTPS_PROXY_REJECT_UNAUTHORIZED', value: 'true' });
    });

    it('should overwrite existing proxy configuration', () => {
      const existingConfig = [
        { key: 'IPINFO_TOKEN', value: 'test-token' },
        { key: 'HTTP_PROXY', value: 'old-proxy' },
        { key: 'NO_PROXY', value: 'old-no-proxy' }
      ];

      const configAdapter = createTestConfigAdapter({
        http_proxy: 'http://new-proxy.example.com:8080',
        https_proxy: '',
        no_proxy: 'localhost',
        https_proxy_ca: [],
        https_proxy_reject_unauthorized: false
      });

      const result = injectProxyConfiguration(existingConfig, configAdapter);

      // Original non-proxy config should be preserved
      expect(result.find((item) => item.key === 'IPINFO_TOKEN')).toEqual({ key: 'IPINFO_TOKEN', value: 'test-token' });

      // Old proxy config should be replaced
      expect(result.filter((item) => item.key === 'HTTP_PROXY')).toHaveLength(1);
      expect(result.find((item) => item.key === 'HTTP_PROXY')).toEqual({ key: 'HTTP_PROXY', value: 'http://new-proxy.example.com:8080' });
      expect(result.find((item) => item.key === 'NO_PROXY')).toEqual({ key: 'NO_PROXY', value: 'localhost' });
      expect(result.find((item) => item.key === 'HTTPS_PROXY_REJECT_UNAUTHORIZED')).toEqual({ key: 'HTTPS_PROXY_REJECT_UNAUTHORIZED', value: 'false' });
    });

    it('should add proxy configuration to empty existing config', () => {
      const existingConfig: Array<{ key: string; value: string }> = [];

      const configAdapter = createTestConfigAdapter({
        http_proxy: 'http://proxy.example.com:8080',
        https_proxy: '',
        no_proxy: '',
        https_proxy_ca: [],
        https_proxy_reject_unauthorized: true
      });

      const result = injectProxyConfiguration(existingConfig, configAdapter);

      // Only non-empty proxy values should be included (http_proxy + reject_unauthorized uppercase only)
      expect(result).toHaveLength(2); // HTTP_PROXY, HTTPS_PROXY_REJECT_UNAUTHORIZED
      expect(result.find((item) => item.key === 'HTTP_PROXY')).toBeDefined();
      expect(result.find((item) => item.key === 'HTTPS_PROXY_REJECT_UNAUTHORIZED')).toBeDefined();
    });
  });
});
