import nconf from 'nconf';
import { booleanConf, loadCert } from '../config/conf';
import { ForbiddenAccess } from '../config/errors';
import { isUserHasCapability } from '../utils/access';
import type { AuthContext, AuthUser } from '../types/user';

interface ProxyUrlConfig {
  url: string;
  enabled: boolean;
}

interface HttpsProxyConfig extends ProxyUrlConfig {
  ca_certificates: string[];
  reject_unauthorized: boolean;
}

interface ExclusionPatterns {
  hostnames: string[];
  ip_ranges: string[];
  wildcards: string[];
}

interface ProxyConfiguration {
  http_proxy: ProxyUrlConfig;
  https_proxy: HttpsProxyConfig;
  no_proxy: string[];
  exclusion_patterns: ExclusionPatterns;
}

// Configuration adapter interface for dependency injection
export interface ConfigAdapter {
  get(key: string): any;
  booleanConf(key: string, defaultValue: boolean): boolean;
  loadCert(cert: string | undefined): string | undefined;
}

// Default adapter using nconf and conf functions
export class DefaultConfigAdapter implements ConfigAdapter {
  // eslint-disable-next-line class-methods-use-this
  get(key: string): any {
    return nconf.get(key);
  }

  // eslint-disable-next-line class-methods-use-this
  booleanConf(key: string, defaultValue: boolean): boolean {
    return booleanConf(key, defaultValue);
  }

  // eslint-disable-next-line class-methods-use-this
  loadCert(cert: string | undefined): string | undefined {
    return loadCert(cert);
  }
}

// Helper function to parse exclusion patterns
const parseExclusionPatterns = (noProxyList: string[]): ExclusionPatterns => {
  const patterns: ExclusionPatterns = {
    hostnames: [],
    ip_ranges: [],
    wildcards: []
  };

  noProxyList.forEach((item) => {
    if (!item) return;

    // Check for IP ranges (IPv4 with optional CIDR)
    if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(item)) {
      patterns.ip_ranges.push(item);
    } else if (item.includes('*') || item.startsWith('.')) {
      // Wildcard patterns
      patterns.wildcards.push(item);
    } else {
      // Regular hostnames
      patterns.hostnames.push(item);
    }
  });

  return patterns;
};

// Main function with optional dependency injection for testing
export const getConnectorProxyConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  // Optional configAdapter parameter for dependency injection.
  // This parameter is used for unit testing purposes only, allowing tests
  // In production, this parameter should not be provided and the default adapter will be used.
  configAdapter: ConfigAdapter = new DefaultConfigAdapter()
): Promise<ProxyConfiguration> => {
  // Check capability
  if (!isUserHasCapability(user, 'CONNECTORAPI')) {
    throw ForbiddenAccess('User does not have CONNECTORAPI capability');
  }

  // Use the provided config adapter to get proxy settings
  // nconf normalizes environment variables to lowercase
  const httpProxy = configAdapter.get('http_proxy') || '';
  const httpsProxy = configAdapter.get('https_proxy') || '';
  const noProxy = (configAdapter.get('no_proxy') || '').split(',').filter(Boolean).map((s: string) => s.trim());

  // Get CA certificates from configuration and load their content
  const proxyCA = configAdapter.get('https_proxy_ca') || [];
  const caCertArray = Array.isArray(proxyCA) ? proxyCA : [proxyCA];
  // Load certificate content (from file if path, or pass through if already content)
  const caCertificates: string[] = caCertArray
    .filter((cert: any) => cert !== null && cert !== undefined && cert !== '')
    .map((cert: string) => configAdapter.loadCert(cert))
    .filter((cert): cert is string => cert !== undefined && cert !== null) as string[];

  return {
    http_proxy: {
      url: httpProxy,
      enabled: !!httpProxy
    },
    https_proxy: {
      url: httpsProxy,
      ca_certificates: caCertificates,
      reject_unauthorized: configAdapter.booleanConf('https_proxy_reject_unauthorized', true),
      enabled: !!httpsProxy
    },
    no_proxy: noProxy,
    exclusion_patterns: parseExclusionPatterns(noProxy)
  };
};
