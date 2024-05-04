import conf, { loadCert, logApp } from './conf';
import { type Certificates, type GetHttpClient, getHttpClient } from '../utils/http-client';
import { isNotEmptyField } from '../database/utils';

const CYBERARK_PROVIDER = 'cyberark';

export const enrichWithRemoteCredentials = async (prefix: string, baseConfiguration: any) => {
  const provider = conf.get(`${prefix}:credentials_provider:selector`);
  if (provider) {
    logApp.info('[OPENCTI] Remote credentials configuration detected', { provider, source: prefix });
    if (provider === CYBERARK_PROVIDER) {
      const uri = conf.get(`${prefix}:credentials_provider:${provider}:uri`);
      const appId = conf.get(`${prefix}:credentials_provider:${provider}:app_id`);
      const safe = conf.get(`${prefix}:credentials_provider:${provider}:safe`);
      const object = conf.get(`${prefix}:credentials_provider:${provider}:object`);
      // https options
      let certs: Certificates | undefined;
      const rejectUnauthorized = conf.get('elasticsearch:credentials_provider:https_cert:reject_unauthorized') || false;
      if (conf.get(`${prefix}:credentials_provider:https_cert:crt`)) {
        certs = {
          cert: conf.get(`${prefix}:credentials_provider:https_cert:crt`),
          key: conf.get(`${prefix}:credentials_provider:https_cert:key`),
          ca: (conf.get(`${prefix}:credentials_provider:https_cert:ca`) ?? []).map((path: string) => loadCert(path)),
        };
      }
      const httpClientOptions: GetHttpClient = { rejectUnauthorized, responseType: 'json', certificates: certs };
      const httpClient = getHttpClient(httpClientOptions);
      const params = { AppID: appId, Safe: safe, Object: object };
      try {
        const secretResult = { ...baseConfiguration };
        const result = await httpClient.get(uri, { params });
        if (result.status === 200 && isNotEmptyField(result.data.Content)) {
          const defaultSplitter = conf.get(`${prefix}:credentials_provider:${provider}:default_splitter`) ?? ':';
          const contentValues = result.data.Content.split(defaultSplitter);
          const fields = conf.get(`${prefix}:credentials_provider:field_targets`);
          for (let index = 0; index < fields.length; index += 1) {
            const field = fields[index];
            secretResult[field] = contentValues[index];
          }
          logApp.info('[OPENCTI] Remote credentials successfully fetched', { provider, source: prefix });
          return secretResult;
        }
      } catch (e: any) {
        logApp.error('[OPENCTI] Remote credentials data fail to fetch, fallback', { error: e, provider, source: prefix });
      }
    }
    // No compatible provider available
    logApp.error('[OPENCTI] Remote credentials provider is not supported, fallback', { provider, source: prefix });
  }
  return baseConfiguration;
};
