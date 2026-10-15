import { pipeline, Readable, Transform } from 'node:stream';
import type { ReadableStream as NodeReadableStream } from 'node:stream/web';
import { Agent, type Dispatcher, fetch, FormData, Headers, type Response } from 'undici';
import { getPlatformHttpProxyAgent } from '../config/conf';
import { fromBase64, isNotEmptyField } from '../database/utils';

export class OpenCTIHeaders {
  [name: string]: string;
}

export interface Certificates {
  cert: string;
  key: string;
  ca: string;
}

export type HttpResponseType = 'json' | 'arraybuffer' | 'text' | 'stream';

export interface GetHttpClient {
  baseURL?: string;
  rejectUnauthorized?: boolean;
  timeout?: number;
  responseType: HttpResponseType;
  headers?: Record<string, string>;
  certificates?: Certificates;
  auth?: {
    username: string;
    password: string;
  };
  beforeRedirect?: (redirectUrl: string) => void;
}

export interface HttpRequestOptions {
  params?: object;
  headers?: Record<string, string>;
  timeout?: number;
  signal?: AbortSignal;
  maxRedirects?: number;
}

export interface HttpRequestConfig extends HttpRequestOptions {
  url: string;
  method?: string;
  data?: unknown;
}

export interface HttpResponse<T = any> {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: T;
}

export class HttpClientError extends Error {
  readonly code?: string;

  readonly status?: number;

  readonly response?: HttpResponse;

  constructor(message: string, code?: string, response?: HttpResponse, options?: ErrorOptions) {
    super(message, options);
    this.name = 'HttpClientError';
    this.code = code;
    this.response = response;
    this.status = response?.status;
  }
}

export interface HttpResponseError {
  status: number;
  data: any;
  headers: Record<string, string>;
  message: string;
}
export const getResponseError = (error: unknown): HttpResponseError | null => {
  if (error instanceof HttpClientError && error.response) {
    return {
      status: error.response.status,
      data: error.response.data,
      headers: error.response.headers,
      message: error.message,
    };
  }
  return null;
};

const DEFAULT_ACCEPT = 'application/json, text/plain, */*';
const DEFAULT_MAX_REDIRECTS = 21;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const METHODS_WITH_DEFAULT_FORM_CONTENT_TYPE = new Set(['POST', 'PUT', 'PATCH']);
const METHODS_WITHOUT_BODY = new Set(['GET', 'HEAD']);
const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);
const FETCH_DECODED_CONTENT_CODINGS = new Set(['gzip', 'x-gzip', 'deflate', 'br', 'zstd']);

const isAbsoluteUrl = (url: string) => /^([a-z][a-z\d+\-.]*:)?\/\//i.test(url);

const combineUrl = (url: string, baseURL?: string) => {
  if (!baseURL || isAbsoluteUrl(url)) {
    return url;
  }
  return url ? `${baseURL.replace(/\/?\/$/, '')}/${url.replace(/^\/+/, '')}` : baseURL;
};

const encodeParam = (value: string) => encodeURIComponent(value)
  .replace(/%3A/gi, ':')
  .replace(/%24/g, '$')
  .replace(/%2C/gi, ',')
  .replace(/%20/g, '+');

const serializeParamValue = (value: unknown) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
};

const buildUrl = (url: string, baseURL: string | undefined, params: object | undefined) => {
  const fullUrl = combineUrl(url, baseURL);
  const serializedParams = Object.entries(params ?? {}).flatMap(([key, value]) => {
    if (value === undefined || value === null) {
      return [];
    }
    if (Array.isArray(value)) {
      return value.filter((v) => v !== undefined && v !== null)
        .map((v) => `${encodeParam(`${key}[]`)}=${encodeParam(serializeParamValue(v))}`);
    }
    return [`${encodeParam(key)}=${encodeParam(serializeParamValue(value))}`];
  }).join('&');
  if (!serializedParams) {
    return fullUrl;
  }
  const hashIndex = fullUrl.indexOf('#');
  const urlWithoutHash = hashIndex === -1 ? fullUrl : fullUrl.slice(0, hashIndex);
  return `${urlWithoutHash}${urlWithoutHash.includes('?') ? '&' : '?'}${serializedParams}`;
};

const buildHeaders = (clientHeaders: Record<string, string> | undefined, requestHeaders: Record<string, string> | undefined) => {
  const headers = new Headers({ Accept: DEFAULT_ACCEPT });
  [clientHeaders, requestHeaders].forEach((source) => {
    Object.entries(source ?? {}).forEach(([name, value]) => {
      if (value !== undefined && value !== null) {
        headers.set(name, String(value));
      }
    });
  });
  return headers;
};

type BasicCredentials = NonNullable<GetHttpClient['auth']>;

const toBasicAuthorization = ({ username, password }: BasicCredentials) => {
  return `Basic ${Buffer.from(`${username || ''}:${password || ''}`, 'utf-8').toString('base64')}`;
};

const decodeUrlComponent = (value: string) => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const extractUrlCredentials = (url: URL): BasicCredentials | undefined => {
  if (!url.username && !url.password) {
    return undefined;
  }
  const credentials = { username: decodeUrlComponent(url.username), password: decodeUrlComponent(url.password) };
  url.username = '';
  url.password = '';
  return credentials;
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const isFormVisitable = (value: unknown) => Array.isArray(value) || isPlainObject(value);

const removeBrackets = (key: string) => (key.endsWith('[]') ? key.slice(0, -2) : key);

const renderFormKey = (path: string[]) => path.map((token, index) => (index ? `[${removeBrackets(token)}]` : removeBrackets(token))).join('');

const toFormValue = (value: unknown) => (value instanceof Date ? value.toISOString() : String(value));

const appendFormEntries = (data: object, append: (key: string, value: string) => void) => {
  const visit = (value: unknown, path: string[]) => {
    if (value === undefined || value === null) {
      return;
    }
    if (path.length === 1 && Array.isArray(value) && (path[0].endsWith('[]') || !value.some(isFormVisitable))) {
      const key = `${removeBrackets(path[0])}[]`;
      value.filter((element) => element !== undefined && element !== null).forEach((element) => append(key, toFormValue(element)));
      return;
    }
    if (isFormVisitable(value)) {
      Object.entries(value as object).forEach(([key, element]) => visit(element, [...path, key.trim()]));
      return;
    }
    append(renderFormKey(path), toFormValue(value));
  };
  Object.entries(data).forEach(([key, value]) => visit(value, [key.trim()]));
};

const stringifyJsonString = (value: string) => {
  try {
    JSON.parse(value);
    return value.trim();
  } catch {
    return JSON.stringify(value);
  }
};

const buildBody = (method: string, data: unknown, headers: Headers): string | Uint8Array | FormData | undefined => {
  if (data === undefined || METHODS_WITHOUT_BODY.has(method)) {
    return undefined;
  }
  const contentType = headers.get('Content-Type') ?? '';
  const hasJsonContentType = contentType.includes('application/json');
  if (data === null) {
    return hasJsonContentType ? 'null' : undefined;
  }
  if (data instanceof URLSearchParams) {
    if (!contentType) {
      headers.set('Content-Type', 'application/x-www-form-urlencoded;charset=utf-8');
    }
    return data.toString();
  }
  if (typeof data === 'string' && hasJsonContentType) {
    return stringifyJsonString(data);
  }
  if (typeof data === 'string' || data instanceof Uint8Array) {
    if (!contentType && METHODS_WITH_DEFAULT_FORM_CONTENT_TYPE.has(method)) {
      headers.set('Content-Type', 'application/x-www-form-urlencoded');
    }
    return data;
  }
  if (typeof data === 'object' && contentType.includes('application/x-www-form-urlencoded')) {
    const form = new URLSearchParams();
    appendFormEntries(data, (key, value) => form.append(key, value));
    return form.toString();
  }
  if (typeof data === 'object' && contentType.includes('multipart/form-data')) {
    const form = new FormData();
    appendFormEntries(data, (key, value) => form.append(key, value));
    headers.delete('Content-Type');
    return form;
  }
  if (!contentType) {
    headers.set('Content-Type', 'application/json');
  }
  return JSON.stringify(data);
};

const isSubdomain = (subdomain: string, domain: string) => {
  const dot = subdomain.length - domain.length - 1;
  return dot > 0 && subdomain[dot] === '.' && subdomain.endsWith(domain);
};

const isUnsafeRedirect = (from: URL, to: URL) => (from.protocol !== to.protocol && to.protocol !== 'https:')
  || (from.host !== to.host && !isSubdomain(to.host, from.host));

const isBodyDecodedByFetch = (method: string, response: Response) => {
  const contentEncoding = response.headers.get('content-encoding');
  if (!contentEncoding || method === 'HEAD' || NULL_BODY_STATUSES.has(response.status)) {
    return false;
  }
  return contentEncoding.toLowerCase().split(',').every((coding) => FETCH_DECODED_CONTENT_CODINGS.has(coding.trim()));
};

const toHeaderRecord = (method: string, response: Response) => {
  const record: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    record[name] = value;
  });
  if (isBodyDecodedByFetch(method, response)) {
    delete record['content-encoding'];
    delete record['content-length'];
  }
  return record;
};

const watchBody = (response: Response, onProgress: () => void, onEnd: () => void) => {
  const source = response.body ? Readable.fromWeb(response.body as NodeReadableStream) : Readable.from([]);
  const watched = new Transform({
    transform(chunk, _encoding, callback) {
      onProgress();
      callback(null, chunk);
    },
  });
  pipeline(source, watched, onEnd);
  return watched;
};

const readData = async (response: Response, responseType: HttpResponseType, onProgress: () => void, onEnd: () => void) => {
  const body = watchBody(response, onProgress, onEnd);
  if (responseType === 'stream') {
    return body;
  }
  const chunks: Buffer[] = [];
  for await (const chunk of body) {
    chunks.push(Buffer.from(chunk));
  }
  const buffer = Buffer.concat(chunks);
  if (responseType === 'arraybuffer') {
    return buffer;
  }
  const text = new TextDecoder().decode(buffer);
  if (responseType === 'text' || !text) {
    return text;
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const buildAgent = (rejectUnauthorized: boolean, certificates: Certificates | undefined) => new Agent({
  headersTimeout: 0,
  bodyTimeout: 0,
  connect: {
    rejectUnauthorized,
    cert: isNotEmptyField(certificates?.cert) ? fromBase64(certificates?.cert) : undefined,
    key: isNotEmptyField(certificates?.key) ? fromBase64(certificates?.key) : undefined,
    ca: isNotEmptyField(certificates?.ca) ? fromBase64(certificates?.ca) : undefined,
  },
});

const sharedAgents = new Map<boolean, Agent>();
const getAgent = (rejectUnauthorized: boolean, certificates: Certificates | undefined) => {
  if (certificates) {
    return buildAgent(rejectUnauthorized, certificates);
  }
  const existing = sharedAgents.get(rejectUnauthorized);
  if (existing) {
    return existing;
  }
  const agent = buildAgent(rejectUnauthorized, undefined);
  sharedAgents.set(rejectUnauthorized, agent);
  return agent;
};

const createTimeoutWatchdog = (timeout: number) => {
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const disarm = () => clearTimeout(timer);
  const arm = () => {
    disarm();
    timer = setTimeout(() => controller.abort(), timeout).unref();
  };
  return { signal: controller.signal, arm, disarm };
};

const toTransportError = (error: unknown, timeout: number, timeoutSignal: AbortSignal | undefined, signal: AbortSignal | undefined) => {
  if (timeoutSignal?.aborted) {
    return new HttpClientError(`timeout of ${timeout}ms exceeded`, 'ECONNABORTED', undefined, { cause: error });
  }
  if (signal?.aborted) {
    return new HttpClientError('canceled', 'ERR_CANCELED', undefined, { cause: error });
  }
  const cause = (error as { cause?: { code?: string; message?: string } })?.cause;
  const message = cause?.message ?? (error as Error)?.message ?? 'Network error';
  return new HttpClientError(message, cause?.code ?? 'ERR_NETWORK', undefined, { cause: error });
};

export const getHttpClient = ({ baseURL, headers, rejectUnauthorized, timeout, responseType, certificates, auth, beforeRedirect }: GetHttpClient) => {
  const clientAgent = getAgent(rejectUnauthorized === true, certificates);
  const defaultAgent = getAgent(true, undefined);
  const request = async (config: HttpRequestConfig, useClientTransport: boolean): Promise<HttpResponse> => {
    const method = (config.method ?? 'GET').toUpperCase();
    const requestTimeout = config.timeout ?? timeout ?? 0;
    const maxRedirects = config.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    const requestHeaders = buildHeaders(headers, config.headers);
    const watchdog = requestTimeout > 0 ? createTimeoutWatchdog(requestTimeout) : undefined;
    const signals = [watchdog?.signal, config.signal].filter((s): s is AbortSignal => s !== undefined);
    const signal = signals.length > 0 ? AbortSignal.any(signals) : undefined;
    const transport = async <T>(operation: () => Promise<T>) => {
      try {
        return await operation();
      } catch (error) {
        throw toTransportError(error, requestTimeout, watchdog?.signal, config.signal);
      }
    };
    let currentUrl = await transport(async () => new URL(buildUrl(config.url, baseURL, config.params)));
    const requestOrigin = currentUrl.origin;
    const urlCredentials = extractUrlCredentials(currentUrl);
    const basicCredentials = auth ?? urlCredentials;
    if (basicCredentials) {
      requestHeaders.set('Authorization', toBasicAuthorization(basicCredentials));
    }
    let currentMethod = method;
    let body = buildBody(method, config.data, requestHeaders);
    let response: Response;
    try {
      for (let redirectCount = 0; ; redirectCount += 1) {
        const dispatcher: Dispatcher = useClientTransport ? (getPlatformHttpProxyAgent(currentUrl.href, true) ?? clientAgent) : defaultAgent;
        const requestInit = { method: currentMethod, headers: requestHeaders, body, signal, redirect: 'manual' as const, dispatcher };
        const requestUrl = currentUrl.href;
        watchdog?.arm();
        response = await transport(() => fetch(requestUrl, requestInit));
        const location = response.headers.get('location');
        if (maxRedirects === 0 || !location || !REDIRECT_STATUSES.has(response.status)) {
          break;
        }
        const redirectResponse = response;
        await transport(async () => redirectResponse.body?.cancel());
        if (redirectCount >= maxRedirects) {
          throw new HttpClientError('Maximum number of redirects exceeded', 'ERR_FR_TOO_MANY_REDIRECTS');
        }
        const fromUrl = currentUrl;
        const toUrl = await transport(async () => new URL(location, fromUrl));
        extractUrlCredentials(toUrl);
        beforeRedirect?.(toUrl.href);
        if ((response.status === 303 && !METHODS_WITHOUT_BODY.has(currentMethod)) || ((response.status === 301 || response.status === 302) && currentMethod === 'POST')) {
          currentMethod = 'GET';
          body = undefined;
          [...requestHeaders.keys()].filter((name) => name.startsWith('content-')).forEach((name) => requestHeaders.delete(name));
        }
        if (isUnsafeRedirect(fromUrl, toUrl)) {
          ['authorization', 'proxy-authorization', 'cookie'].forEach((name) => requestHeaders.delete(name));
        }
        if (basicCredentials) {
          if (toUrl.origin === requestOrigin) {
            requestHeaders.set('Authorization', toBasicAuthorization(basicCredentials));
          } else {
            requestHeaders.delete('Authorization');
          }
        }
        currentUrl = toUrl;
      }
    } catch (error) {
      watchdog?.disarm();
      throw error;
    }
    const finalResponse = response;
    const ok = finalResponse.status >= 200 && finalResponse.status < 300;
    const httpResponse: HttpResponse = {
      status: finalResponse.status,
      statusText: finalResponse.statusText,
      headers: toHeaderRecord(currentMethod, finalResponse),
      data: await transport(() => {
        watchdog?.arm();
        return readData(finalResponse, ok ? responseType : 'json', () => watchdog?.arm(), () => watchdog?.disarm());
      }),
    };
    if (!ok) {
      const code = finalResponse.status >= 500 ? 'ERR_BAD_RESPONSE' : (finalResponse.status >= 400 ? 'ERR_BAD_REQUEST' : undefined);
      throw new HttpClientError(`Request failed with status code ${finalResponse.status}`, code, httpResponse);
    }
    return httpResponse;
  };
  return {
    call: (config: HttpRequestConfig) => request(config, false),
    get: async (url: string, opts: HttpRequestOptions = {}) => request({ ...opts, url, method: 'GET' }, true),
    post: async (url: string, data: unknown, opts: HttpRequestOptions = {}) => request({ ...opts, url, method: 'POST', data }, true),
    delete: async (url: string, opts: HttpRequestOptions = {}) => request({ ...opts, url, method: 'DELETE' }, true),
    head: async (url: string, opts: HttpRequestOptions = {}) => request({ ...opts, url, method: 'HEAD' }, true),
  };
};
