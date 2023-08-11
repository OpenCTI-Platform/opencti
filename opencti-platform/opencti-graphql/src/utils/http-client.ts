import https from 'node:https';
import axios, { AxiosHeaders } from 'axios';
import { getPlatformHttpProxies } from '../config/conf';

export interface GetHttpClient {
  rejectUnauthorized?: boolean
  responseType: 'json' | 'arraybuffer' | 'text'
  headers?: AxiosHeaders
}
export const getHttpClient = ({ headers, rejectUnauthorized, responseType }: GetHttpClient) => {
  const proxies = getPlatformHttpProxies();
  const defaultHttpsAgent = new https.Agent({ rejectUnauthorized: rejectUnauthorized === true });
  return axios.create({
    responseType,
    headers,
    httpAgent: proxies['http:']?.build(),
    httpsAgent: proxies['https:']?.build() ?? defaultHttpsAgent,
  });
};
