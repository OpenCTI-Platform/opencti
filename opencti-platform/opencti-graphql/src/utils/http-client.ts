import axios, { AxiosHeaders } from 'axios';
import https from 'node:https';
import { getPlatformHttpProxies } from '../config/conf';

interface GetHttpClient {
  rejectUnauthorized?: boolean
  responseType: 'json' | 'arraybuffer'
  headers: AxiosHeaders
}
export const getHttpClient = ({ headers, rejectUnauthorized, responseType }: GetHttpClient) => {
  const proxies = getPlatformHttpProxies();
  const defaultHttpsAgent = new https.Agent({ rejectUnauthorized: rejectUnauthorized ?? true });
  return axios.create({
    responseType,
    headers,
    httpAgent: proxies['http:'],
    httpsAgent: proxies['https:'] ?? defaultHttpsAgent,
  });
};
