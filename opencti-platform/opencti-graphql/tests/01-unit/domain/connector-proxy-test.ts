import { describe, it, expect } from 'vitest';
import { getConnectorProxyConfiguration } from '../../../src/domain/connector-proxy';
import type { ConfigAdapter } from '../../../src/domain/connector-proxy';
import { ADMIN_USER, testContext, buildStandardUser } from '../../utils/testQuery';

// Test adapter implementation for unit tests
class TestConfigAdapter implements ConfigAdapter {
  constructor(private values: Record<string, any>) {}

  get(key: string): any {
    return this.values[key];
  }

  booleanConf(key: string, defaultValue: boolean): boolean {
    const value = this.values[key];
    if (value === '0' || value === 'false' || value === false) return false;
    if (value === '1' || value === 'true' || value === true) return true;
    if (value === undefined || value === null) return defaultValue;
    return defaultValue;
  }

  // eslint-disable-next-line class-methods-use-this
  loadCert(cert: string | undefined): string | undefined {
    if (!cert) return undefined;
    // If it starts with -----BEGIN, return as-is (already certificate content)
    if (cert.startsWith('-----BEGIN')) {
      return cert;
    }
    // Otherwise, simulate reading file and returning content
    return `-----BEGIN CERTIFICATE-----\nMOCKED_CONTENT_FOR_${cert}\n-----END CERTIFICATE-----`;
  }
}

describe('Connector Proxy resolver tests', () => {
  describe('getConnectorProxyConfiguration', () => {
    it('should deny access to users without CONNECTORAPI capability', async () => {
      // Create a user without CONNECTORAPI capability
      const userWithoutCapability = buildStandardUser(
        [],
        [],
        [{ name: 'KNOWLEDGE_KNUPDATE_KNDELETE' }]
      );

      const configAdapter = new TestConfigAdapter({});

      // Should throw ForbiddenAccess error
      await expect(
        getConnectorProxyConfiguration(testContext, userWithoutCapability, configAdapter)
      ).rejects.toThrow('User does not have CONNECTORAPI capability');
    });

    it('should allow access to admin users with BYPASS capability', async () => {
      const configAdapter = new TestConfigAdapter({
        http_proxy: 'http://proxy.example.com:8080',
        https_proxy: '',
        no_proxy: 'localhost,127.0.0.1,.internal.domain',
        https_proxy_ca: []
      });

      // Admin user has BYPASS capability
      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      expect(result).toBeDefined();
      expect(result.http_proxy).toEqual({
        url: 'http://proxy.example.com:8080',
        enabled: true,
      });
      expect(result.no_proxy).toContain('localhost');
      expect(result.no_proxy).toContain('127.0.0.1');
      expect(result.no_proxy).toContain('.internal.domain');
    });

    it('should allow access to users with CONNECTORAPI capability', async () => {
      // Create a user with CONNECTORAPI capability
      const connectorUser = buildStandardUser(
        [],
        [],
        [{ name: 'CONNECTORAPI' }]
      );

      const configAdapter = new TestConfigAdapter({
        http_proxy: 'http://proxy.example.com:8080',
        https_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = await getConnectorProxyConfiguration(testContext, connectorUser, configAdapter);

      expect(result).toBeDefined();
      expect(result.http_proxy).toEqual({
        url: 'http://proxy.example.com:8080',
        enabled: true,
      });
    });

    it('should return empty proxy configuration when no proxy is set', async () => {
      const configAdapter = new TestConfigAdapter({
        http_proxy: '',
        https_proxy: '',
        no_proxy: '',
        https_proxy_ca: [],
        https_proxy_reject_unauthorized: undefined
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      expect(result).toEqual({
        http_proxy: {
          url: '',
          enabled: false,
        },
        https_proxy: {
          url: '',
          ca_certificates: [],
          reject_unauthorized: true,
          enabled: false,
        },
        no_proxy: [],
        exclusion_patterns: {
          hostnames: [],
          ip_ranges: [],
          wildcards: [],
        },
      });
    });

    it('should handle credentials in proxy URLs correctly', async () => {
      const configAdapter = new TestConfigAdapter({
        http_proxy: 'http://username:password@proxy.example.com:8080',
        https_proxy: 'https://user:pass@secure-proxy.example.com:8443',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      // Should preserve credentials in the URL
      expect(result.http_proxy.url).toBe('http://username:password@proxy.example.com:8080');
      expect(result.https_proxy.url).toBe('https://user:pass@secure-proxy.example.com:8443');
    });

    it('should parse NO_PROXY exclusion patterns correctly', async () => {
      const configAdapter = new TestConfigAdapter({
        no_proxy: 'localhost,127.0.0.1,192.168.1.0/24,*.internal.com,.example.org,specific.domain.com',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      expect(result.exclusion_patterns.hostnames).toContain('localhost');
      expect(result.exclusion_patterns.hostnames).toContain('specific.domain.com');
      expect(result.exclusion_patterns.ip_ranges).toContain('127.0.0.1');
      expect(result.exclusion_patterns.ip_ranges).toContain('192.168.1.0/24');
      expect(result.exclusion_patterns.wildcards).toContain('*.internal.com');
      expect(result.exclusion_patterns.wildcards).toContain('.example.org');
    });

    it('should handle CA certificates from configuration', async () => {
      const configAdapter = new TestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/ca-cert.pem', '/path/to/ssl-cert.pem', '/path/to/ca-bundle.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      // Now we expect certificate content, not paths
      expect(result.https_proxy.ca_certificates).toHaveLength(3);
      expect(result.https_proxy.ca_certificates[0]).toContain('-----BEGIN CERTIFICATE-----');
      expect(result.https_proxy.ca_certificates[0]).toContain('MOCKED_CONTENT_FOR_/path/to/ca-cert.pem');
      expect(result.https_proxy.ca_certificates[1]).toContain('MOCKED_CONTENT_FOR_/path/to/ssl-cert.pem');
      expect(result.https_proxy.ca_certificates[2]).toContain('MOCKED_CONTENT_FOR_/path/to/ca-bundle.pem');
      expect(result.https_proxy.enabled).toBe(true);
    });

    it('should handle https_proxy_reject_unauthorized setting', async () => {
      // Test with rejection disabled
      const configAdapter1 = new TestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_reject_unauthorized: '0',
        http_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      let result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter1);
      expect(result.https_proxy.reject_unauthorized).toBe(false);

      // Test with rejection enabled
      const configAdapter2 = new TestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_reject_unauthorized: '1',
        http_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter2);
      expect(result.https_proxy.reject_unauthorized).toBe(true);

      // Test with undefined (default to true)
      const configAdapter3 = new TestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_reject_unauthorized: undefined,
        http_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter3);
      expect(result.https_proxy.reject_unauthorized).toBe(true);
    });

    it('should handle malformed proxy URLs gracefully', async () => {
      const configAdapter = new TestConfigAdapter({
        http_proxy: 'not-a-valid-url',
        https_proxy: 'also-invalid',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      // Should still return the URLs as-is for the caller to handle
      expect(result.http_proxy.url).toBe('not-a-valid-url');
      expect(result.https_proxy.url).toBe('also-invalid');
    });

    it('should handle empty but defined proxy variables', async () => {
      const configAdapter = new TestConfigAdapter({
        http_proxy: '',
        https_proxy: '',
        no_proxy: '',
        https_proxy_ca: []
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      expect(result.http_proxy.url).toBe('');
      expect(result.http_proxy.enabled).toBe(false);
      expect(result.https_proxy.url).toBe('');
      expect(result.https_proxy.enabled).toBe(false);
      expect(result.no_proxy).toEqual([]);
    });

    it('should handle whitespace in NO_PROXY correctly', async () => {
      const configAdapter = new TestConfigAdapter({
        no_proxy: ' localhost , 127.0.0.1 , *.internal.com ',
        http_proxy: '',
        https_proxy: '',
        https_proxy_ca: []
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      // Should trim whitespace
      expect(result.no_proxy).toContain('localhost');
      expect(result.no_proxy).toContain('127.0.0.1');
      expect(result.no_proxy).toContain('*.internal.com');
      expect(result.no_proxy).toHaveLength(3);
    });

    it('should handle CA certificates as a single string', async () => {
      const configAdapter = new TestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: '/path/to/single-cert.pem',
        http_proxy: '',
        no_proxy: ''
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      expect(result.https_proxy.ca_certificates).toHaveLength(1);
      // Now we expect certificate content, not path
      expect(result.https_proxy.ca_certificates[0]).toContain('-----BEGIN CERTIFICATE-----');
      expect(result.https_proxy.ca_certificates[0]).toContain('MOCKED_CONTENT_FOR_/path/to/single-cert.pem');
    });

    it('should filter out empty CA certificate entries', async () => {
      const configAdapter = new TestConfigAdapter({
        https_proxy: 'https://secure-proxy.example.com:8443',
        https_proxy_ca: ['/path/to/cert1.pem', '', null, '/path/to/cert2.pem'],
        http_proxy: '',
        no_proxy: ''
      });

      const result = await getConnectorProxyConfiguration(testContext, ADMIN_USER, configAdapter);

      expect(result.https_proxy.ca_certificates).toHaveLength(2);
      // Now we expect certificate content, not paths
      expect(result.https_proxy.ca_certificates[0]).toContain('-----BEGIN CERTIFICATE-----');
      expect(result.https_proxy.ca_certificates[0]).toContain('MOCKED_CONTENT_FOR_/path/to/cert1.pem');
      expect(result.https_proxy.ca_certificates[1]).toContain('MOCKED_CONTENT_FOR_/path/to/cert2.pem');
    });
  });
});
