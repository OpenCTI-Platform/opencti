import { once } from 'node:events';
import type http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { testSync } from '../../../src/domain/connector-utils';
import * as httpConfig from '../../../src/http/httpConfig';
import { buildSelfSignedCertificate } from '../../utils/selfSignedCertificate';
import { testContext, ADMIN_USER } from '../../utils/testQuery';

// Global tls:reject_unauthorized switch, the real configuration value is used when not overridden
const tlsConfig = vi.hoisted(() => ({ rejectUnauthorized: undefined as boolean | undefined }));
// outbound_requests configuration, the real configuration values are used when not overridden
const outboundConfig = vi.hoisted(() => ({ blocked: undefined as boolean | undefined, allowList: undefined as string[] | undefined }));
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    // No platform proxy, whatever the test configuration: the connections are checked by the socket lookup
    getPlatformHttpProxyAgent: () => undefined,
    get TLS_REJECT_UNAUTHORIZED() {
      return tlsConfig.rejectUnauthorized ?? actual.TLS_REJECT_UNAUTHORIZED;
    },
    get OUTBOUND_BLOCK_INTERNAL_DESTINATIONS() {
      return outboundConfig.blocked ?? actual.OUTBOUND_BLOCK_INTERNAL_DESTINATIONS;
    },
    get OUTBOUND_ALLOW_LIST() {
      return outboundConfig.allowList ?? actual.OUTBOUND_ALLOW_LIST;
    },
  };
});

// Remote OpenCTI stream served over https with a self-signed certificate
let server: https.Server;
let remoteUri: string;
// Another server, on another origin (port), the remote OpenCTI can redirect to
let otherServer: https.Server;
let otherUri: string;
// The authorization header received by each server, by path
const receivedAuthorizations: { server: string; path: string | undefined; authorization: string | undefined }[] = [];

const serveStream = (res: http.ServerResponse) => {
  res.writeHead(200, { 'Content-Type': 'text/event-stream' });
  res.write(`event: connected\ndata: ${JSON.stringify({ connectionId: 'connection-id' })}\n\n`);
};

const listen = async (target: https.Server) => {
  target.listen(0, '127.0.0.1');
  await once(target, 'listening');
  return `https://127.0.0.1:${(target.address() as AddressInfo).port}`;
};

beforeAll(async () => {
  server = https.createServer(buildSelfSignedCertificate(), (req, res) => {
    receivedAuthorizations.push({ server: 'remote', path: req.url, authorization: req.headers.authorization });
    if (req.url === '/stream/redirect-to-ip-address') {
      res.writeHead(302, { Location: `${remoteUri}/stream/live` }).end();
      return;
    }
    if (req.url === '/stream/redirect-to-same-origin') {
      res.writeHead(302, { Location: '/stream/live' }).end();
      return;
    }
    if (req.url === '/stream/redirect-to-other-origin') {
      res.writeHead(302, { Location: `${otherUri}/stream/live` }).end();
      return;
    }
    serveStream(res);
  });
  otherServer = https.createServer(buildSelfSignedCertificate(), (req, res) => {
    receivedAuthorizations.push({ server: 'other', path: req.url, authorization: req.headers.authorization });
    serveStream(res);
  });
  remoteUri = await listen(server);
  otherUri = await listen(otherServer);
});

afterAll(async () => {
  [server, otherServer].forEach((target) => {
    target.closeAllConnections();
    target.close();
  });
});

describe('testSync TLS certificate verification', () => {
  const buildSync = (sslVerify?: boolean | null) => ({ uri: remoteUri, stream_id: 'live', token: '', ssl_verify: sslVerify });

  afterEach(() => {
    tlsConfig.rejectUnauthorized = undefined;
  });

  it.each([undefined, null, false])('should accept an untrusted certificate by default when ssl_verify is %s', async (sslVerify) => {
    await expect(testSync(testContext, ADMIN_USER, buildSync(sslVerify))).resolves.toBe('Connection success');
  });

  it('should reject an untrusted certificate when ssl_verify is enabled', async () => {
    await expect(testSync(testContext, ADMIN_USER, buildSync(true))).rejects.toThrow('Cant connect to remote opencti');
  });

  it.each([undefined, null])('should reject an untrusted certificate when enabled globally and ssl_verify is %s', async (sslVerify) => {
    tlsConfig.rejectUnauthorized = true;
    await expect(testSync(testContext, ADMIN_USER, buildSync(sslVerify))).rejects.toThrow('Cant connect to remote opencti');
  });

  it('should let ssl_verify override the global switch', async () => {
    tlsConfig.rejectUnauthorized = true;
    await expect(testSync(testContext, ADMIN_USER, buildSync(false))).resolves.toBe('Connection success');
  });
});

describe('testSync internal destinations', () => {
  afterEach(() => {
    outboundConfig.blocked = undefined;
    outboundConfig.allowList = undefined;
    vi.restoreAllMocks();
  });

  it('should reject a remote OpenCTI on an internal network when internal destinations are blocked', async () => {
    outboundConfig.blocked = true;
    await expect(testSync(testContext, ADMIN_USER, { uri: remoteUri, stream_id: 'live', token: '', ssl_verify: false }))
      .rejects.toThrow('Synchronizer: the destination 127.0.0.1 is an internal network address');
  });

  it('should reject a remote OpenCTI host name resolving to an internal network when internal destinations are blocked', async () => {
    outboundConfig.blocked = true;
    await expect(testSync(testContext, ADMIN_USER, { uri: remoteUri.replace('127.0.0.1', 'localhost'), stream_id: 'live', token: '', ssl_verify: false }))
      .rejects.toThrow('Synchronizer: the destination localhost is an internal network address');
  });

  it('should reject a redirect of the remote OpenCTI to an internal network when internal destinations are blocked', async () => {
    outboundConfig.blocked = true;
    outboundConfig.allowList = ['localhost'];
    const localhostUri = remoteUri.replace('127.0.0.1', 'localhost');
    await expect(testSync(testContext, ADMIN_USER, { uri: localhostUri, stream_id: 'live', token: '', ssl_verify: false })).resolves.toBe('Connection success');
    await expect(testSync(testContext, ADMIN_USER, { uri: localhostUri, stream_id: 'redirect-to-ip-address', token: '', ssl_verify: false }))
      .rejects.toThrow('Synchronizer: the destination 127.0.0.1 is an internal network address');
  });

  it('should follow a redirect of the remote OpenCTI when internal destinations are not blocked', async () => {
    outboundConfig.blocked = false;
    await expect(testSync(testContext, ADMIN_USER, { uri: remoteUri, stream_id: 'redirect-to-ip-address', token: '', ssl_verify: false })).resolves.toBe('Connection success');
  });

  it('should not follow a redirect of the remote OpenCTI beyond the maximum number of redirects', async () => {
    outboundConfig.blocked = false;
    vi.spyOn(httpConfig, 'getHttpMaxRedirects').mockReturnValue(0);
    await expect(testSync(testContext, ADMIN_USER, { uri: remoteUri, stream_id: 'redirect-to-ip-address', token: '', ssl_verify: false })).rejects.toThrow();
  });
});

describe('testSync token on redirects', () => {
  const TOKEN = 'remote-opencti-token';
  const buildSync = (streamId: string) => ({ uri: remoteUri, stream_id: streamId, token: TOKEN, ssl_verify: false });

  beforeEach(() => {
    receivedAuthorizations.length = 0;
  });

  afterEach(() => {
    outboundConfig.blocked = undefined;
  });

  it('should send the token again after a redirect to the same origin', async () => {
    outboundConfig.blocked = false;
    await expect(testSync(testContext, ADMIN_USER, buildSync('redirect-to-same-origin'))).resolves.toBe('Connection success');
    expect(receivedAuthorizations).toEqual([
      { server: 'remote', path: '/stream/redirect-to-same-origin', authorization: `Bearer ${TOKEN}` },
      { server: 'remote', path: '/stream/live', authorization: `Bearer ${TOKEN}` },
    ]);
  });

  it('should not send the token after a redirect to another origin', async () => {
    outboundConfig.blocked = false;
    await expect(testSync(testContext, ADMIN_USER, buildSync('redirect-to-other-origin'))).resolves.toBe('Connection success');
    expect(receivedAuthorizations).toEqual([
      { server: 'remote', path: '/stream/redirect-to-other-origin', authorization: `Bearer ${TOKEN}` },
      { server: 'other', path: '/stream/live', authorization: undefined },
    ]);
  });
});
