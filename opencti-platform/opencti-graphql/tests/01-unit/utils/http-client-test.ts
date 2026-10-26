import { generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import http from 'node:http';
import https from 'node:https';
import net, { type AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import forge from 'node-forge';
import { ProxyAgent } from 'undici';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { getPlatformHttpProxyAgent } from '../../../src/config/conf';
import { getHttpClient, getResponseError, HttpClientError } from '../../../src/utils/http-client';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...actual, getPlatformHttpProxyAgent: vi.fn(() => undefined) };
});

interface ReceivedRequest {
  method?: string;
  url?: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

const received: ReceivedRequest[] = [];
const servers: http.Server[] = [];
let baseURL: string;
let otherHostBaseURL: string;
let closedPortURL: string;
let selfSignedBaseURL: string;
let selfSignedCertificate: { key: string; cert: string };
let mutualTlsBaseURL: string;
let proxyURL: string;
const proxiedTargets: string[] = [];

const routes: Record<string, (req: http.IncomingMessage, res: http.ServerResponse) => void> = {
  '/json': (_req, res) => res.writeHead(200, { 'Content-Type': 'application/json', 'X-Custom': 'value' }).end('{"hello":"world"}'),
  '/not-json': (_req, res) => res.writeHead(200).end('plain text'),
  '/empty': (_req, res) => res.writeHead(204).end(),
  '/bad-request': (_req, res) => res.writeHead(400, { 'Content-Type': 'application/json' }).end('{"detail":"invalid input"}'),
  '/server-error': (_req, res) => res.writeHead(503).end('down'),
  '/slow': (_req, res) => setTimeout(() => res.writeHead(200).end('late'), 500),
  '/gzip': (_req, res) => res.writeHead(200, { 'Content-Encoding': 'gzip', 'Content-Type': 'text/plain' }).end(gzipSync('decoded content')),
  '/redirect': (_req, res) => res.writeHead(302, { Location: '/json' }).end(),
  '/redirect-loop': (_req, res) => res.writeHead(302, { Location: '/redirect-loop' }).end(),
  '/redirect-other-host': (_req, res) => res.writeHead(307, { Location: `${otherHostBaseURL}/echo` }).end(),
  '/redirect-echo': (_req, res) => res.writeHead(302, { Location: '/echo' }).end(),
  '/redirect-with-credentials': (_req, res) => res.writeHead(302, { Location: `${baseURL.replace('://', '://intruder:secret@')}/echo` }).end(),
  '/trickle': (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    let sent = 0;
    const timer = setInterval(() => {
      sent += 1;
      res.write('a');
      if (sent === 6) {
        clearInterval(timer);
        res.end();
      }
    }, 40);
  },
  '/stall': (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write('a');
    setTimeout(() => res.end('b'), 400);
  },
  '/error-never-ends': (_req, res) => {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.write('{"detail":"unavailable"}');
  },
  '/error-then-reset': (_req, res) => {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.write('{"detail":"unavailable"}');
    setTimeout(() => res.socket?.destroy(), 50);
  },
  '/gzip-trickle': (_req, res) => {
    res.writeHead(200, { 'Content-Encoding': 'gzip', 'Content-Type': 'text/plain' });
    const compressed = gzipSync('compressed trickle content');
    let offset = 0;
    const timer = setInterval(() => {
      res.write(compressed.subarray(offset, offset + 1));
      offset += 1;
      if (offset === compressed.length) {
        clearInterval(timer);
        res.end();
      }
    }, 20);
  },
  '/client-certificate': (req, res) => {
    const peerCertificate = (req.socket as TLSSocket).getPeerCertificate();
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ subject: peerCertificate?.subject?.CN ?? null }));
  },
  '/echo': (req, res) => res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(received[received.length - 1])),
};

const handleRequest = (req: http.IncomingMessage, res: http.ServerResponse) => {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
  });
  req.on('end', () => {
    received.push({ method: req.method, url: req.url, headers: req.headers, body });
    const route = routes[new URL(req.url ?? '/', 'http://localhost').pathname];
    if (route) {
      route(req, res);
    } else {
      res.writeHead(404).end();
    }
  });
};

const buildSelfSignedCertificate = () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = forge.pki.publicKeyFromPem(publicKey);
  certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date(Date.now() - 60_000);
  certificate.validity.notAfter = new Date(Date.now() + 3_600_000);
  const attributes = [{ name: 'commonName', value: '127.0.0.1' }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 7, ip: '127.0.0.1' }] }]);
  certificate.sign(forge.pki.privateKeyFromPem(privateKey), forge.md.sha256.create());
  return { key: privateKey, cert: forge.pki.certificateToPem(certificate) };
};

const startServer = async (tls?: https.ServerOptions) => {
  const server = tls ? https.createServer(tls, handleRequest) : http.createServer(handleRequest);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  servers.push(server);
  return `${tls ? 'https' : 'http'}://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

const closeServer = (server: http.Server) => new Promise((resolve) => {
  server.close(resolve);
  server.closeAllConnections();
});

beforeAll(async () => {
  baseURL = await startServer();
  otherHostBaseURL = await startServer();
  closedPortURL = await startServer();
  await closeServer(servers.pop() as http.Server);
  selfSignedCertificate = buildSelfSignedCertificate();
  selfSignedBaseURL = await startServer(selfSignedCertificate);
  mutualTlsBaseURL = await startServer({ ...selfSignedCertificate, requestCert: true, rejectUnauthorized: false });
  const proxy = http.createServer((_req, res) => res.writeHead(405).end());
  proxy.on('connect', (req: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) => {
    proxiedTargets.push(req.url ?? '');
    const [host, port] = (req.url ?? '').split(':');
    const targetSocket = net.connect(Number(port), host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      targetSocket.write(head);
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
    });
    targetSocket.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => targetSocket.destroy());
  });
  await new Promise<void>((resolve) => {
    proxy.listen(0, '127.0.0.1', resolve);
  });
  servers.push(proxy);
  proxyURL = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await Promise.all(servers.map(closeServer));
});

const lastRequest = () => received[received.length - 1];

describe('getHttpClient', () => {
  it('should parse json responses and expose lower-cased headers', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'json' }).get('/json');

    expect(response.status).toBe(200);
    expect(response.data).toEqual({ hello: 'world' });
    expect(response.headers['x-custom']).toBe('value');
  });

  it('should keep the raw text when a json response cannot be parsed', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'json' }).get('/not-json');

    expect(response.data).toBe('plain text');
  });

  it('should return an empty string for an empty json response', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'json' }).get('/empty');

    expect(response.status).toBe(204);
    expect(response.data).toBe('');
  });

  it('should return a buffer for arraybuffer responses and a node stream for stream responses', async () => {
    const bufferResponse = await getHttpClient({ baseURL, responseType: 'arraybuffer' }).get('/not-json');
    const streamResponse = await getHttpClient({ baseURL, responseType: 'stream' }).get('/not-json');

    expect(Buffer.isBuffer(bufferResponse.data)).toBe(true);
    expect(bufferResponse.data.toString()).toBe('plain text');
    expect(streamResponse.data).toBeInstanceOf(Readable);
    const chunks: Buffer[] = [];
    for await (const chunk of streamResponse.data) {
      chunks.push(Buffer.from(chunk));
    }
    expect(Buffer.concat(chunks).toString()).toBe('plain text');
  });

  it('should serialize query params and append them to an existing query string', async () => {
    await getHttpClient({ baseURL, responseType: 'json' }).get('/json?existing=1', {
      params: { next: 'a b:c', added_after: undefined, limit: 10, empty: null },
    });

    expect(lastRequest().url).toBe('/json?existing=1&next=a+b:c&limit=10');
  });

  it('should send headers, basic authentication and a json body', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json', headers: { 'X-Api-Key': 'secret' }, auth: { username: 'user', password: 'pässword' } });

    await client.post('/json', { key: 'value' });

    const request = lastRequest();
    expect(request.method).toBe('POST');
    expect(request.headers['x-api-key']).toBe('secret');
    expect(request.headers.accept).toBe('application/json, text/plain, */*');
    expect(request.headers.authorization).toBe(`Basic ${Buffer.from('user:pässword', 'utf-8').toString('base64')}`);
    expect(request.headers['content-type']).toBe('application/json');
    expect(request.body).toBe('{"key":"value"}');
  });

  it('should send a string body as form data unless a content type is provided', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json' });

    await client.post('/json', 'a=1');
    const defaultContentType = lastRequest().headers['content-type'];
    await client.call({ url: '/json', method: 'POST', data: '{"a":1}', headers: { 'Content-Type': 'application/json' } });
    const providedContentType = lastRequest().headers['content-type'];

    expect(defaultContentType).toBe('application/x-www-form-urlencoded');
    expect(providedContentType).toBe('application/json');
    expect(lastRequest().body).toBe('{"a":1}');
  });

  it('should reject a client error with the response attached', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'json' }).get('/bad-request').catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.message).toBe('Request failed with status code 400');
    expect(error.code).toBe('ERR_BAD_REQUEST');
    expect(error.status).toBe(400);
    expect(getResponseError(error)).toMatchObject({ status: 400, data: { detail: 'invalid input' } });
  });

  it('should reject a server error with the bad response code', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'text' }).get('/server-error').catch((e) => e);

    expect(error.code).toBe('ERR_BAD_RESPONSE');
    expect(error.response.data).toBe('down');
  });

  it('should reject an error response without waiting for a streamed body that never ends', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'stream' }).get('/error-never-ends').catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.status).toBe(503);
    expect(error.response.data).toBeInstanceOf(Readable);
    const [chunk] = await once(error.response.data, 'data');
    expect(chunk.toString()).toBe('{"detail":"unavailable"}');
    error.response.data.destroy();
  });

  it('should reject with a timeout error when the response is too slow', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'text', timeout: 50 }).get('/slow').catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('ECONNABORTED');
    expect(error.message).toBe('timeout of 50ms exceeded');
  });

  it('should reject with a canceled error when the caller aborts', async () => {
    const controller = new AbortController();
    const pending = getHttpClient({ baseURL, responseType: 'text' }).get('/slow', { signal: controller.signal });
    controller.abort();

    await expect(pending).rejects.toMatchObject({ code: 'ERR_CANCELED' });
  });

  it('should reject with the transport error code when the server is unreachable', async () => {
    const error = await getHttpClient({ responseType: 'json' }).get(closedPortURL).catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('ECONNREFUSED');
    expect(error.response).toBeUndefined();
  });

  it('should follow redirects, downgrading a redirected POST to GET, and report each target to beforeRedirect', async () => {
    const redirects: string[] = [];
    const client = getHttpClient({ baseURL, responseType: 'json', beforeRedirect: (url) => redirects.push(url) });

    const response = await client.post('/redirect', { key: 'value' });

    expect(response.data).toEqual({ hello: 'world' });
    expect(redirects).toEqual([`${baseURL}/json`]);
    expect(lastRequest().method).toBe('GET');
    expect(lastRequest().body).toBe('');
    expect(lastRequest().headers['content-type']).toBeUndefined();
  });

  it('should abort the redirect when beforeRedirect throws', async () => {
    const rejectRedirect = () => {
      throw new Error('forbidden target');
    };
    const client = getHttpClient({ baseURL, responseType: 'json', beforeRedirect: rejectRedirect });

    await expect(client.get('/redirect')).rejects.toThrow('forbidden target');
  });

  it('should not follow redirects when maxRedirects is 0', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'json' }).get('/redirect', { maxRedirects: 0 }).catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.status).toBe(302);
  });

  it('should stop after too many redirects', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'json' }).get('/redirect-loop', { maxRedirects: 3 }).catch((e) => e);

    expect(error.code).toBe('ERR_FR_TOO_MANY_REDIRECTS');
  });

  it('should drop credentials when redirected to another host', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json', headers: { Authorization: 'Bearer token', Cookie: 'session=1' } });

    const response = await client.get('/redirect-other-host');

    expect(response.data.headers.authorization).toBeUndefined();
    expect(response.data.headers.cookie).toBeUndefined();
  });

  it('should drop the encoding headers of a body that was decoded', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'text' }).get('/gzip');

    expect(response.data).toBe('decoded content');
    expect(response.headers['content-encoding']).toBeUndefined();
    expect(response.headers['content-length']).toBeUndefined();
    expect(response.headers['content-type']).toBe('text/plain');
  });

  it('should send the credentials of the url as basic authentication', async () => {
    const response = await getHttpClient({ responseType: 'json' }).get(`${baseURL.replace('://', '://user:p%40ss@')}/echo`);

    expect(response.data.headers.authorization).toBe(`Basic ${Buffer.from('user:p@ss').toString('base64')}`);
  });

  it('should prefer the explicit authentication over the url credentials and the authorization header', async () => {
    const client = getHttpClient({ responseType: 'json', headers: { Authorization: 'Bearer token' }, auth: { username: 'explicit', password: 'secret' } });

    const response = await client.get(`${baseURL.replace('://', '://user:pass@')}/echo`);

    expect(response.data.headers.authorization).toBe(`Basic ${Buffer.from('explicit:secret').toString('base64')}`);
  });

  it('should keep basic authentication on a same-origin redirect only', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json', auth: { username: 'user', password: 'secret' } });

    const sameOrigin = await client.get('/redirect-echo');
    const otherHost = await client.get('/redirect-other-host');

    expect(sameOrigin.data.headers.authorization).toBe(`Basic ${Buffer.from('user:secret').toString('base64')}`);
    expect(otherHost.data.headers.authorization).toBeUndefined();
  });

  it('should ignore the credentials of a redirect location', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'json' }).get('/redirect-with-credentials');

    expect(response.data.url).toBe('/echo');
    expect(response.data.headers.authorization).toBeUndefined();
  });

  it('should form-encode an object payload sent as application/x-www-form-urlencoded', async () => {
    const data = { message: 'hello world', count: 2, ok: true, skip: null, nested: { key: 'v', deep: { x: 'y' } }, list: ['a', 'b'], objs: [{ k: 1 }, { k: 2 }], 'tags[]': ['t1'] };

    const response = await getHttpClient({ baseURL, responseType: 'json' }).call({
      url: '/echo',
      method: 'POST',
      data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    expect(response.data.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(response.data.body).toBe('message=hello+world&count=2&ok=true&nested%5Bkey%5D=v&nested%5Bdeep%5D%5Bx%5D=y&list%5B%5D=a&list%5B%5D=b&objs%5B0%5D%5Bk%5D=1&objs%5B1%5D%5Bk%5D=2&tags%5B%5D=t1');
  });

  it('should send an object payload sent as multipart/form-data as form fields', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'json' }).call({
      url: '/echo',
      method: 'POST',
      data: { message: 'hello world', nested: { key: 'v' } },
      headers: { 'Content-Type': 'multipart/form-data' },
    });

    expect(response.data.headers['content-type']).toMatch(/^multipart\/form-data; boundary=/);
    expect(response.data.body).toContain('name="message"\r\n\r\nhello world\r\n');
    expect(response.data.body).toContain('name="nested[key]"\r\n\r\nv\r\n');
  });

  it('should reject an untrusted certificate unless certificate verification is disabled', async () => {
    const verified = await getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized: true }).get('/not-json').catch((e) => e);
    const unverified = await getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized: false }).get('/not-json');

    expect(verified).toBeInstanceOf(HttpClientError);
    expect(verified.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(unverified.data).toBe('plain text');
  });

  it.each([undefined, null])('should verify the certificate by default when rejectUnauthorized is %s', async (rejectUnauthorized) => {
    const error = await getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized }).get('/not-json').catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
  });

  it('should always verify the certificate on call', async () => {
    const client = getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized: false });

    const error = await client.call({ url: '/not-json', method: 'POST', data: {} }).catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
  });

  it('should honor the certificate verification option on request', async () => {
    const config = { url: '/not-json', method: 'POST', data: {} };

    const unverified = await getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized: false }).request(config);
    const verified = await getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized: true }).request(config).catch((e) => e);

    expect(unverified.data).toBe('plain text');
    expect(verified).toBeInstanceOf(HttpClientError);
    expect(verified.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
  });

  it('should use the client certificates on request', async () => {
    const toBase64 = (value: string) => Buffer.from(value).toString('base64');
    const certificates = { cert: toBase64(selfSignedCertificate.cert), key: toBase64(selfSignedCertificate.key), ca: toBase64(selfSignedCertificate.cert) };
    const client = getHttpClient({ baseURL: mutualTlsBaseURL, responseType: 'json', rejectUnauthorized: true, certificates });

    const response = await client.request({ url: '/client-certificate', method: 'GET' });
    const callError = await client.call({ url: '/client-certificate', method: 'GET' }).catch((e) => e);

    expect(response.data).toEqual({ subject: '127.0.0.1' });
    expect(callError).toBeInstanceOf(HttpClientError);
    expect(callError.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
  });

  it('should go through the platform proxy on request but not on call', async () => {
    const proxyAgentMock = vi.mocked(getPlatformHttpProxyAgent);
    proxyAgentMock.mockReturnValueOnce(new ProxyAgent({ uri: proxyURL, proxyTunnel: true }));
    const client = getHttpClient({ baseURL, responseType: 'json' });
    const target = new URL(baseURL).host;

    const response = await client.request({ url: '/json', method: 'GET' });
    const proxiedAfterRequest = [...proxiedTargets];
    await client.call({ url: '/json', method: 'GET' });

    expect(response.data).toEqual({ hello: 'world' });
    expect(proxiedAfterRequest).toEqual([target]);
    expect(proxiedTargets).toEqual([target]);
    expect(proxyAgentMock).toHaveBeenCalledTimes(1);
  });

  it('should not time out a body that keeps arriving after the timeout duration', async () => {
    const client = getHttpClient({ baseURL, responseType: 'text', timeout: 100 });

    const response = await client.get('/trickle');
    const streamResponse = await getHttpClient({ baseURL, responseType: 'stream', timeout: 100 }).get('/trickle');
    const chunks: Buffer[] = [];
    for await (const chunk of streamResponse.data) {
      chunks.push(Buffer.from(chunk));
    }

    expect(response.data).toBe('aaaaaa');
    expect(Buffer.concat(chunks).toString()).toBe('aaaaaa');
  });

  it('should time out a body that stops arriving', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'text', timeout: 100 }).get('/stall').catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('ECONNABORTED');
  });

  it('should serialize string and null payloads sent as application/json', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json', headers: { 'Content-Type': 'application/json' } });

    const plainString = await client.post('/echo', 'hello');
    const jsonString = await client.post('/echo', ' {"a":1} ');
    const nullPayload = await client.call({ url: '/echo', method: 'POST', data: null });

    expect(plainString.data.body).toBe('"hello"');
    expect(jsonString.data.body).toBe('{"a":1}');
    expect(nullPayload.data.body).toBe('null');
  });

  it('should report a streamed body that stops arriving as a timeout', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'stream', timeout: 100 }).get('/stall');

    const error = await (async () => {
      for await (const chunk of response.data) {
        expect(chunk.toString()).toBe('a');
      }
    })().catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('ECONNABORTED');
  });

  it('should report a streamed body canceled by the caller as canceled', async () => {
    const controller = new AbortController();
    const response = await getHttpClient({ baseURL, responseType: 'stream' }).get('/stall', { signal: controller.signal });

    const error = await (async () => {
      for await (const chunk of response.data) {
        expect(chunk.toString()).toBe('a');
        controller.abort();
      }
    })().catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('ERR_CANCELED');
  });

  it('should not raise an unhandled error when an unread error stream fails', async () => {
    const error = await getHttpClient({ baseURL, responseType: 'stream' }).get('/error-then-reset').catch((e) => e);

    expect(error.status).toBe(503);
    await new Promise((resolve) => {
      error.response.data.on('close', resolve);
    });
    expect(error.response.data.errored).toBeInstanceOf(HttpClientError);
  });

  it('should not time out a compressed body whose bytes keep arriving', async () => {
    const response = await getHttpClient({ baseURL, responseType: 'text', timeout: 100 }).get('/gzip-trickle');

    expect(response.data).toBe('compressed trickle content');
  });

  it('should read an error response with the requested response type', async () => {
    const textError = await getHttpClient({ baseURL, responseType: 'text' }).get('/bad-request').catch((e) => e);
    const bufferError = await getHttpClient({ baseURL, responseType: 'arraybuffer' }).get('/server-error').catch((e) => e);

    expect(textError.response.data).toBe('{"detail":"invalid input"}');
    expect(Buffer.isBuffer(bufferError.response.data)).toBe(true);
    expect(bufferError.response.data.toString()).toBe('down');
  });
});
