import http from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// No platform proxy is configured: the client falls back to its default agents,
// and the spy records which target URL the proxy lookup was asked about.
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return { ...actual, getPlatformHttpProxyAgent: vi.fn(() => undefined) };
});

import { getPlatformHttpProxyAgent } from '../../../src/config/conf';
import { getHttpClient } from '../../../src/utils/http-client';

interface ReceivedRequest {
  method?: string;
  url?: string;
  contentType?: string;
  body: string;
}

describe('http-client: patch', () => {
  let server: http.Server;
  let baseURL: string;
  const received: ReceivedRequest[] = [];

  beforeAll(async () => {
    server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        received.push({
          method: req.method,
          url: req.url,
          contentType: req.headers['content-type'],
          body: Buffer.concat(chunks).toString('utf-8'),
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: '42', title: 'Renamed' }));
      });
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const { port } = server.address() as AddressInfo;
    baseURL = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    server.close();
    await once(server, 'close');
  });

  beforeEach(() => {
    received.length = 0;
    vi.mocked(getPlatformHttpProxyAgent).mockClear();
  });

  it('should send a PATCH with the JSON body and answer the upstream response', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json' });

    const response = await client.patch('/api/v1/items/42', { title: 'Renamed' }, { timeout: 5000 });

    expect(response.status).toBe(200);
    expect(response.data).toEqual({ id: '42', title: 'Renamed' });
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ method: 'PATCH', url: '/api/v1/items/42', body: '{"title":"Renamed"}' });
    expect(received[0].contentType).toContain('application/json');
  });

  it('should pick the agent for the absolute target URL, like the other methods', async () => {
    const client = getHttpClient({ baseURL, responseType: 'json' });

    await client.patch('/api/v1/items/42', { title: 'Renamed' });

    expect(getPlatformHttpProxyAgent).toHaveBeenCalledWith(`${baseURL}/api/v1/items/42`);
  });
});
