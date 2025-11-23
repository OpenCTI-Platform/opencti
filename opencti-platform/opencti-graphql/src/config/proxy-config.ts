import nconf from 'nconf';
import { booleanConf, loadCert, logApp } from './conf';

// Default configuration constants
const DEFAULT_HTTPS_PROXY_REJECT_UNAUTHORIZED = true;

export type ConfigAdapter = {
  get(key: string): any;
  booleanConf(key: string, defaultValue: boolean): boolean;
  loadCert(cert: string | undefined): string | undefined;
};

export const createDefaultConfigAdapter = (): ConfigAdapter => ({
  get: (key: string) => nconf.get(key),
  booleanConf: (key: string, defaultValue: boolean) => booleanConf(key, defaultValue),
  loadCert: (cert: string | undefined) => loadCert(cert)
});

const validateNoProxyForUrllib = (noProxyList: string[]): string[] => {
  const validEntries: string[] = [];
  const invalidEntries: string[] = [];

  noProxyList.forEach((item) => {
    if (!item) return;
    if (item.includes('*') && !item.startsWith('.')) {
      invalidEntries.push(item);
    } else if (/\/\d{1,2}$/.test(item)) {
      invalidEntries.push(item);
    } else {
      validEntries.push(item);
    }
  });

  if (invalidEntries.length > 0) {
    logApp.warn('[OPENCTI] The following NO_PROXY entries are not compatible with Python urllib.request and will be excluded:', {
      invalid_entries: invalidEntries,
      reason: 'urllib.request does not support wildcard (*) patterns or CIDR notation (/24). Use leading dot (.example.com) for subdomain matching.'
    });
  }

  return validEntries;
};

const validateProxyUrl = (url: string, proxyType: string): boolean => {
  if (!url) return true;
  try {
    const parsed = new URL(url);
    const validProtocols = ['http:', 'https:', 'socks4:', 'socks5:'];
    if (!validProtocols.includes(parsed.protocol)) {
      logApp.warn(`[OPENCTI] Invalid ${proxyType} protocol`, {
        url,
        protocol: parsed.protocol,
        valid_protocols: validProtocols
      });
      return false;
    }
    return true;
  } catch (e) {
    logApp.warn(`[OPENCTI] Invalid ${proxyType} URL format`, {
      url,
      error: e instanceof Error ? e.message : String(e)
    });
    return false;
  }
};

const processProxyCACertificates = (
  proxyCA: any,
  configAdapter: ConfigAdapter
): string[] => {
  if (proxyCA === undefined || proxyCA === null || proxyCA === '') {
    return [];
  }

  if (!Array.isArray(proxyCA)) {
    logApp.error('[OPENCTI] https_proxy_ca must be an array of certificate paths or contents', {
      received_type: typeof proxyCA,
      received_value: String(proxyCA).substring(0, 100)
    });
    return [];
  }

  if (proxyCA.length === 0) {
    return [];
  }

  const caCertificates: string[] = [];
  const errors: Array<{ cert: any; reason: string }> = [];

  proxyCA.forEach((cert: any, _index: number) => {
    if (cert === null || cert === undefined || cert === '') {
      errors.push({ cert: String(cert), reason: 'Empty or null value' });
      return;
    }
    if (typeof cert !== 'string') {
      errors.push({ cert: String(cert), reason: `Invalid type: ${typeof cert}` });
      return;
    }

    try {
      const loadedCert = configAdapter.loadCert(cert);
      if (loadedCert === undefined || loadedCert === null || loadedCert === '') {
        errors.push({ cert, reason: 'Failed to load certificate (empty result)' });
      } else {
        caCertificates.push(loadedCert);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      errors.push({ cert, reason: `Failed to load certificate: ${errorMessage}` });
    }
  });

  if (errors.length > 0) {
    logApp.warn('[OPENCTI] Some CA certificates could not be loaded', {
      failed_count: errors.length,
      total_count: proxyCA.length,
      errors: errors.map((e, i) => ({
        index: i,
        value: e.cert.substring(0, 100),
        reason: e.reason
      }))
    });
  }

  if (caCertificates.length > 0) {
    logApp.info('[OPENCTI] Successfully loaded CA certificates', {
      count: caCertificates.length
    });
  }

  return caCertificates;
};

const proxyConfigCache = new WeakMap<ConfigAdapter, Record<string, string>>();

const defaultConfigAdapter = createDefaultConfigAdapter();

export const getProxyConfigurationForContract = (
  configAdapter: ConfigAdapter = defaultConfigAdapter
): Record<string, string> => {
  const cached = proxyConfigCache.get(configAdapter);
  if (cached) {
    return cached;
  }

  const httpProxy = configAdapter.get('http_proxy');
  const httpsProxy = configAdapter.get('https_proxy');

  const httpProxyValid = validateProxyUrl(httpProxy, 'http_proxy');
  const httpsProxyValid = validateProxyUrl(httpsProxy, 'https_proxy');

  const finalHttpProxy = httpProxyValid ? httpProxy : '';
  const finalHttpsProxy = httpsProxyValid ? httpsProxy : '';

  const noProxyRaw: string[] = (configAdapter.get('no_proxy') || '')
    .split(',')
    .filter(Boolean)
    .map((s: string) => s.trim())
    .filter((s: string) => s !== '');

  const noProxyUnique = [...new Set(noProxyRaw)];

  const noProxy = validateNoProxyForUrllib(noProxyUnique);

  const proxyCA = configAdapter.get('https_proxy_ca');
  const caCertificates = processProxyCACertificates(proxyCA, configAdapter);

  const config: Record<string, string> = {};

  if (finalHttpProxy) {
    config.HTTP_PROXY = finalHttpProxy;
  }

  if (finalHttpsProxy) {
    config.HTTPS_PROXY = finalHttpsProxy;
  }

  if (noProxy.length > 0) {
    const noProxyValue = noProxy.join(',');
    config.NO_PROXY = noProxyValue;
  }

  if (caCertificates.length > 0) {
    const caCertValue = caCertificates.join('\n');
    config.HTTPS_CA_CERTIFICATES = caCertValue;
  }

  const rejectUnauthorized = String(configAdapter.booleanConf('https_proxy_reject_unauthorized', DEFAULT_HTTPS_PROXY_REJECT_UNAUTHORIZED));
  config.HTTPS_PROXY_REJECT_UNAUTHORIZED = rejectUnauthorized;

  proxyConfigCache.set(configAdapter, config);
  return config;
};

export const injectProxyConfiguration = (
  existingConfig: Array<{ key: string; value: string }>,
  configAdapter: ConfigAdapter = defaultConfigAdapter
): Array<{ key: string; value: string }> => {
  const proxyConfig = getProxyConfigurationForContract(configAdapter);
  const filteredConfig = existingConfig.filter(
    (item) => !['HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'HTTPS_CA_CERTIFICATES', 'HTTPS_PROXY_REJECT_UNAUTHORIZED'].includes(item.key)
  );
  const proxyConfigArray = Object.entries(proxyConfig).map(([key, value]) => ({
    key,
    value
  }));
  return [...filteredConfig, ...proxyConfigArray];
};
