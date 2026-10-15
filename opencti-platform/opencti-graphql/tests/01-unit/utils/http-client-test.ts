import { generateKeyPairSync } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import forge from 'node-forge';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getHttpClient, getResponseError, HttpClientError } from '../../../src/utils/http-client';

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

const startServer = async (tls?: { key: string; cert: string }) => {
  const server = tls ? https.createServer(tls, handleRequest) : http.createServer(handleRequest);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  servers.push(server);
  return `${tls ? 'https' : 'http'}://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

const closeServer = (server: http.Server) => new Promise((resolve) => {
  server.close(resolve);
});

beforeAll(async () => {
  baseURL = await startServer();
  otherHostBaseURL = await startServer();
  closedPortURL = await startServer();
  await closeServer(servers.pop() as http.Server);
  selfSignedBaseURL = await startServer(buildSelfSignedCertificate());
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
    const error = await getHttpClient({ baseURL, responseType: 'stream' }).get('/server-error').catch((e) => e);

    expect(error.code).toBe('ERR_BAD_RESPONSE');
    expect(error.response.data).toBe('down');
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
    const unverified = await getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text' }).get('/not-json');

    expect(verified).toBeInstanceOf(HttpClientError);
    expect(verified.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(unverified.data).toBe('plain text');
  });

  it('should always verify the certificate on call', async () => {
    const client = getHttpClient({ baseURL: selfSignedBaseURL, responseType: 'text', rejectUnauthorized: false });

    const error = await client.call({ url: '/not-json', method: 'POST', data: {} }).catch((e) => e);

    expect(error).toBeInstanceOf(HttpClientError);
    expect(error.code).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
  });
});
