import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { decideEngineClient, probeEngine, resolveEngineClient } from '../../../src/database/engine-detection';

describe('engine detection: decideEngineClient', () => {
  it.each([
    ['Elasticsearch 8', { version: { number: '8.19.0', build_flavor: 'default' } }, 'elasticsearch8'],
    ['Elasticsearch 9', { version: { number: '9.1.0', build_flavor: 'default' } }, 'elasticsearch9'],
    ['a future Elasticsearch major', { version: { number: '10.0.0' } }, 'elasticsearch9'],
    ['Elasticsearch 7, kept on the 8.x client', { version: { number: '7.17.28' } }, 'elasticsearch8'],
    ['an unreadable version, kept on the 8.x client', { version: { number: 'not-a-version' } }, 'elasticsearch8'],
    ['no version at all, kept on the 8.x client', {}, 'elasticsearch8'],
    ['Elastic Serverless, whatever its version number', { version: { number: '8.11.0', build_flavor: 'serverless' } }, 'elasticsearch9'],
    ['OpenSearch', { version: { distribution: 'opensearch', number: '3.7.0' } }, 'opensearch'],
    ['OpenSearch in compatibility mode', { version: { number: '7.10.2' }, tagline: 'The OpenSearch Project: https://opensearch.org/' }, 'opensearch'],
    ['an unknown distribution, treated as Elasticsearch', { version: { distribution: 'other', number: '8.5.0' } }, 'elasticsearch8'],
  ])('should map %s', (_label, info, expected) => {
    expect(decideEngineClient(info)).toBe(expected);
  });
});

describe('engine detection: resolveEngineClient', () => {
  it('should read the server in auto mode', async () => {
    const probe = vi.fn(async () => ({ version: { number: '9.1.0' } }));
    expect(await resolveEngineClient('auto', null, probe)).toEqual({ client: 'elasticsearch9', version: '9.1.0', source: 'detection' });
    expect(probe).toHaveBeenCalledOnce();
  });

  it('should trust a forced client without reading the server', async () => {
    const probe = vi.fn();
    expect(await resolveEngineClient('elasticsearch8', null, probe)).toEqual({ client: 'elasticsearch8', source: 'configuration' });
    expect(probe).not.toHaveBeenCalled();
  });

  it('should refuse an unknown client', async () => {
    await expect(resolveEngineClient('elk', null, vi.fn())).rejects.toThrow('Invalid elasticsearch:engine_client');
  });

  it('should pick OpenSearch with AWS SigV4 without reading the server', async () => {
    const probe = vi.fn();
    expect(await resolveEngineClient('auto', 'eu-west-1', probe)).toEqual({ client: 'opensearch', source: 'aws' });
    expect(probe).not.toHaveBeenCalled();
  });

  it('should accept OpenSearch forced with AWS SigV4, and refuse an Elasticsearch client', async () => {
    expect((await resolveEngineClient('opensearch', 'eu-west-1', vi.fn())).client).toBe('opensearch');
    await expect(resolveEngineClient('elasticsearch9', 'eu-west-1', vi.fn())).rejects.toThrow('must be opensearch with AWS SigV4');
  });
});

describe('engine detection: probeEngine', () => {
  let server: Server;
  let baseUrl: string;
  let lastHeaders: IncomingHttpHeaders = {};
  let answer: { status: number; body: string } = { status: 200, body: '{}' };

  beforeAll(async () => {
    server = createServer((req, res) => {
      lastHeaders = req.headers;
      res.writeHead(answer.status, { 'content-type': 'application/json' });
      res.end(answer.body);
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => {
      server.close(resolve);
    });
  });

  const connection = (overrides: Record<string, unknown> = {}) => ({
    url: baseUrl, auth: {}, rejectUnauthorized: true, timeout: 5000, ...overrides,
  });

  it('should return the server answer, sent with basic credentials', async () => {
    answer = { status: 200, body: JSON.stringify({ version: { number: '9.1.0' } }) };
    const info = await probeEngine(connection({ auth: { username: 'elastic', password: 'changeme' } }));

    expect(info.version?.number).toBe('9.1.0');
    expect(lastHeaders.authorization).toBe(`Basic ${Buffer.from('elastic:changeme').toString('base64')}`);
  });

  it('should send an API key, given encoded or as id and key', async () => {
    answer = { status: 200, body: '{}' };
    await probeEngine(connection({ auth: { apiKey: 'ZW5jb2RlZA==' } }));
    expect(lastHeaders.authorization).toBe('ApiKey ZW5jb2RlZA==');
    await probeEngine(connection({ auth: { apiKey: { id: 'id', api_key: 'key' } } }));
    expect(lastHeaders.authorization).toBe(`ApiKey ${Buffer.from('id:key').toString('base64')}`);
  });

  it('should use credentials written in the URL, without sending them in the URL', async () => {
    answer = { status: 200, body: '{}' };
    await probeEngine(connection({ url: baseUrl.replace('http://', 'http://user:p%40ss@') }));
    expect(lastHeaders.authorization).toBe(`Basic ${Buffer.from('user:p@ss').toString('base64')}`);
  });

  it('should stop on a refused probe, such as a missing privilege', async () => {
    answer = { status: 403, body: '{"error":"forbidden"}' };
    await expect(probeEngine(connection())).rejects.toThrow('refused the version probe');
  });

  it('should stop on an unreadable answer', async () => {
    answer = { status: 200, body: 'not json' };
    await expect(probeEngine(connection())).rejects.toThrow('unreadable response');
  });

  it('should stop when the server cannot be reached', async () => {
    await expect(probeEngine(connection({ url: 'http://127.0.0.1:1' }))).rejects.toThrow('Search engine seems down');
  });
});
