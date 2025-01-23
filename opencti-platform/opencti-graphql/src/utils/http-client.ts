import http from 'node:http';
import https from 'node:https';
import axios, { AxiosHeaders, type AxiosRequestConfig, type HeadersDefaults, type RawAxiosRequestHeaders } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';
import { getPlatformHttpProxyAgent } from '../config/conf';
import { fromBase64, isNotEmptyField } from '../database/utils';

export class OpenCTIHeaders extends AxiosHeaders {}

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

const buildHttpAgentOpts = (uri: string, baseURL: string | undefined, defaultHttpAgent: HttpAgent, defaultHttpsAgent: HttpsAgent) => {
  const agentUri = baseURL ? `${baseURL}${uri}` : uri;
  return {
    httpAgent: getPlatformHttpProxyAgent(agentUri) ?? defaultHttpAgent,
    httpsAgent: getPlatformHttpProxyAgent(agentUri) ?? defaultHttpsAgent,
    proxy: false // Disable direct proxy protocol in http adapter
  };
};
export const getHttpClient = ({ baseURL, headers, rejectUnauthorized, responseType, certificates, auth }: GetHttpClient) => {
  // Build a default https agent to force query options if no proxy is setup
  const cert = isNotEmptyField(certificates?.cert) ? fromBase64(certificates?.cert) : undefined;
  const key = isNotEmptyField(certificates?.key) ? fromBase64(certificates?.key) : undefined;
  const ca = isNotEmptyField(certificates?.ca) ? fromBase64(certificates?.ca) : undefined;
  const defaultHttpAgent = new http.Agent();
  const defaultHttpsAgent = new https.Agent({ rejectUnauthorized: rejectUnauthorized === true, cert, key, ca });
  // Create the default caller
  const caller = axios.create({
    baseURL,
    responseType,
    headers,
    auth,
    withCredentials: true,
  });
  // Override methods to setup correct http agents
  return {
    call: (config: AxiosRequestConfig) => caller(config),
    get: async (url: string, opts: any = {}) => caller.get(url, { ...opts, ...buildHttpAgentOpts(url, baseURL, defaultHttpAgent, defaultHttpsAgent) }),
    post: async (url: string, data: object, opts: any = {}) => caller.post(url, data, { ...opts, ...buildHttpAgentOpts(url, baseURL, defaultHttpAgent, defaultHttpsAgent) }),
    delete: async (url: string, opts: any = {}) => caller.delete(url, { ...opts, ...buildHttpAgentOpts(url, baseURL, defaultHttpAgent, defaultHttpsAgent) }),
  };
};
