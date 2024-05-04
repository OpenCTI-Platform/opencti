import conf, { loadCert, logApp } from './conf';
import { getHttpClient } from '../utils/http-client';
import { ConfigurationError } from './errors';

const CYBERARK_PROVIDER = 'cyberark';

export const resolveSecret = async (prefix) => {
  const provider = conf.get(`${prefix}:credentials_provider:selector`);
  if (provider) {
    logApp.info('[OPENCTI] Resolve secret configuration detected', { provider, source: prefix });
    if (provider === CYBERARK_PROVIDER) {
      const uri = conf.get(`${prefix}:credentials_provider:${provider}:uri`);
      const appId = conf.get(`${prefix}:credentials_provider:${provider}:app_id`);
      const safe = conf.get(`${prefix}:credentials_provider:${provider}:safe`);
      const object = conf.get(`${prefix}:credentials_provider:${provider}:object`);
      // https options
      let certificates = null;
      const rejectUnauthorized = conf.get('elasticsearch:credentials_provider:https_cert:reject_unauthorized') || true;
      if (conf.get(`${prefix}:credentials_provider:https_cert:crt`)) {
        certificates = {
          cert: conf.get(`${prefix}:credentials_provider:https_cert:crt`),
          key: conf.get(`${prefix}:credentials_provider:https_cert:key`),
          ca: (conf.get(`${prefix}:credentials_provider:https_cert:ca`) ?? []).map((path) => loadCert(path)),
        };
      }
      const httpClientOptions = { rejectUnauthorized, responseType: 'json', certificates };
      const httpClient = getHttpClient(httpClientOptions);
      const params = { AppID: appId, Safe: safe, Object: object };
      try {
        const result = await httpClient.get(uri, { params });
        if (result.status === 200 && result.data.Content) {
          const field = conf.get(`${prefix}:credentials_provider:${provider}:field_target`);
          return { field, secret: result.data.Content };
        }
      } catch (e) {
        throw ConfigurationError('[SEARCH] Credential secret fail to fetch', { error: e.code, provider });
      }
      throw ConfigurationError('[SEARCH] Credential secret not found', { object, provider });
    }
    // No compatible provider available
    throw ConfigurationError('[SEARCH] Credential provider is not supported', { provider });
  }
  return undefined;
};
