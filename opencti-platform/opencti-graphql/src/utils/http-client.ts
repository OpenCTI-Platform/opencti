import https from 'node:https';
import axios, { AxiosHeaders } from 'axios';
import { getPlatformHttpProxies } from '../config/conf';
import { fromBase64, isNotEmptyField } from '../database/utils';

export interface Certificates {
  cert: string,
  key: string,
  ca: string,
}
export interface GetHttpClient {
  rejectUnauthorized?: boolean
  responseType: 'json' | 'arraybuffer' | 'text'
  headers?: AxiosHeaders
  certificates?: Certificates
}
export const getHttpClient = ({ headers, rejectUnauthorized, responseType, certificates }: GetHttpClient) => {
  const proxies = getPlatformHttpProxies();
  const cert = isNotEmptyField(certificates?.cert) ? fromBase64(certificates?.cert) : undefined;
  const key = isNotEmptyField(certificates?.key) ? fromBase64(certificates?.key) : undefined;
  const ca = isNotEmptyField(certificates?.ca) ? fromBase64(certificates?.ca) : undefined;
  const defaultHttpsAgent = new https.Agent({ rejectUnauthorized: rejectUnauthorized === true, cert, key, ca });
  return axios.create({
    responseType,
    headers,
    httpAgent: proxies['http:']?.build(),
    httpsAgent: proxies['https:']?.build() ?? defaultHttpsAgent,
  });
};
