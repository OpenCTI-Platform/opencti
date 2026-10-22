// region Search engine client detection
// Decides which client OpenCTI uses to talk to its search engine: the Elasticsearch 8.x
// client, the Elasticsearch 9.x client or the OpenSearch client, in this order:
//   1. a forced client (elasticsearch:engine_client), trusted as is, without reading the server;
//   2. AWS SigV4 (opensearch:region): the OpenSearch client, without reading the server;
//   3. otherwise a GET / on the engine URL, with the platform's own connection settings, read
//      by decideEngineClient. Any failure stops the platform: no silent fallback.
import { Agent, type Dispatcher, fetch, ProxyAgent } from 'undici';
import semver from 'semver';
import { ConfigurationError } from '../config/errors';

export const ENGINE_CLIENT_AUTO = 'auto';
export const ENGINE_CLIENTS = ['elasticsearch8', 'elasticsearch9', 'opensearch'] as const;
export type EngineClient = typeof ENGINE_CLIENTS[number];

export interface EngineInfo {
  version?: { number?: string; distribution?: string; build_flavor?: string };
  tagline?: string;
}

export interface EngineDecision {
  client: EngineClient;
  // Empty when the client was not detected (forced or AWS): the server was not read
  version?: string;
  source: 'configuration' | 'aws' | 'detection';
}

export interface EngineConnection {
  url: string | string[];
  auth: { username?: string | null; password?: string | null; apiKey?: string | { id: string; api_key: string } | null };
  ca?: string | Buffer | null;
  rejectUnauthorized: boolean;
  proxy?: string | null;
  timeout: number;
}

// The answer of GET / decides the client:
//   - OpenSearch announces itself in `distribution`. In compatibility mode (OpenSearch 1.x and 2.x
//     with `compatibility.override_main_response_version`), `distribution` is hidden and the
//     version reads 7.10.2: the tagline still names OpenSearch;
//   - Elastic Serverless gets the newest client: its version number is not meaningful, and Elastic
//     recommends recognizing it by `build_flavor`;
//   - Elasticsearch 9 and later get the 9.x client. Every other answer, Elasticsearch 8, 7 or an
//     unreadable version, keeps the 8.x client, as the platform always did.
export const decideEngineClient = (info: EngineInfo): EngineClient => {
  const distribution = info.version?.distribution;
  if (distribution === 'opensearch' || info.tagline?.includes('OpenSearch')) {
    return 'opensearch';
  }
  if (info.version?.build_flavor === 'serverless') {
    return 'elasticsearch9';
  }
  const major = semver.coerce(info.version?.number ?? '')?.major ?? 8;
  return major >= 9 ? 'elasticsearch9' : 'elasticsearch8';
};

const authorizationHeader = (auth: EngineConnection['auth'], url: URL): string | undefined => {
  if (auth.apiKey) {
    const key = typeof auth.apiKey === 'string' ? auth.apiKey : Buffer.from(`${auth.apiKey.id}:${auth.apiKey.api_key}`).toString('base64');
    return `ApiKey ${key}`;
  }
  // Credentials may also be written in the URL, which the Elastic and OpenSearch clients accept
  const username = auth.username || decodeURIComponent(url.username);
  const password = auth.password || decodeURIComponent(url.password);
  if (username) {
    return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  }
  return undefined;
};

// GET / on the engine, with the same TLS, credentials, proxy and timeout as the clients
export const probeEngine = async (connection: EngineConnection): Promise<EngineInfo> => {
  const node = Array.isArray(connection.url) ? connection.url[0] : connection.url;
  const url = new URL(node);
  const authorization = authorizationHeader(connection.auth, url);
  url.username = '';
  url.password = '';
  const tls = { ca: connection.ca ?? undefined, rejectUnauthorized: connection.rejectUnauthorized };
  const dispatcher: Dispatcher = connection.proxy
    ? new ProxyAgent({ uri: connection.proxy, requestTls: tls })
    : new Agent({ connect: tls });
  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { accept: 'application/json', ...(authorization ? { authorization } : {}) },
      dispatcher,
      signal: AbortSignal.timeout(connection.timeout),
    });
  } catch (cause) {
    throw ConfigurationError('Search engine seems down', { url: url.origin, cause });
  } finally {
    // The dispatcher only serves this probe
    dispatcher.close().catch(() => {});
  }
  if (!response.ok) {
    throw ConfigurationError('Search engine refused the version probe (GET /)', { url: url.origin, http_status: response.status });
  }
  try {
    return await response.json() as EngineInfo;
  } catch (cause) {
    throw ConfigurationError('Search engine answered GET / with an unreadable response', { url: url.origin, cause });
  }
};

export const resolveEngineClient = async (
  forced: string,
  awsRegion: string | null | undefined,
  probe: () => Promise<EngineInfo>,
): Promise<EngineDecision> => {
  if (forced !== ENGINE_CLIENT_AUTO) {
    if (!(ENGINE_CLIENTS as readonly string[]).includes(forced)) {
      throw ConfigurationError('Invalid elasticsearch:engine_client', { configured: forced, allowed: [ENGINE_CLIENT_AUTO, ...ENGINE_CLIENTS] });
    }
    // SigV4 signing is only wired on the OpenSearch client
    if (awsRegion && forced !== 'opensearch') {
      throw ConfigurationError('elasticsearch:engine_client must be opensearch with AWS SigV4 (opensearch:region)', { configured: forced });
    }
    return { client: forced as EngineClient, source: 'configuration' };
  }
  if (awsRegion) {
    return { client: 'opensearch', source: 'aws' };
  }
  const info = await probe();
  return { client: decideEngineClient(info), version: info.version?.number, source: 'detection' };
};
// endregion
