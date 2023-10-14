import https from 'node:https';
import axios, { type AxiosHeaders, type HeadersDefaults, type RawAxiosRequestHeaders } from 'axios';
import { getPlatformHttpProxies } from '../config/conf';
import { fromBase64, isNotEmptyField } from '../database/utils';

export interface Certificates {
  cert: string,
  key: string,
  ca: string,
}
export interface GetHttpClient {
  baseURL?: string
  rejectUnauthorized?: boolean
  responseType: 'json' | 'arraybuffer' | 'text'
  headers?: RawAxiosRequestHeaders | AxiosHeaders | Partial<HeadersDefaults>;
  certificates?: Certificates
  auth? : {
    username: string
    password: string
  }
}
export const getHttpClient = ({ baseURL, headers, rejectUnauthorized, responseType, certificates, auth }: GetHttpClient) => {
  const proxies = getPlatformHttpProxies();
  const cert = isNotEmptyField(certificates?.cert) ? fromBase64(certificates?.cert) : undefined;
  const key = isNotEmptyField(certificates?.key) ? fromBase64(certificates?.key) : undefined;
  const ca = isNotEmptyField(certificates?.ca) ? fromBase64(certificates?.ca) : undefined;
  const defaultHttpsAgent = new https.Agent({ rejectUnauthorized: rejectUnauthorized === true, cert, key, ca });
  return axios.create({
    baseURL,
    responseType,
    headers,
    auth,
    withCredentials: true,
    httpAgent: proxies['http:']?.build(),
    httpsAgent: proxies['https:']?.build() ?? defaultHttpsAgent,
    proxy: false // Disable direct proxy protocol in axios http adapter
  });
};
