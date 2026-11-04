import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';

const TILES_FILE = fileURLToPath(new URL('../../data/test-map-file.pmtiles', import.meta.url));
const COUNTRIES_FILE = fileURLToPath(new URL('../../data/test-countries.json', import.meta.url));

vi.mock('../../../src/database/raw-file-storage', async () => {
  const actual = await vi.importActual<typeof import('../../../src/database/raw-file-storage')>(
    '../../../src/database/raw-file-storage',
  );
  return {
    ...actual,
    downloadFile: vi.fn(async () => null),
    downloadFileRange: async () => null,
    getFileMetadata: vi.fn(async () => null),
  };
});

interface TestFeature {
  properties: { ISO3: string };
}

interface TestCollection {
  type: string;
  features: TestFeature[];
}

let server: Server;
let origin: string;

beforeAll(async () => {
  const express = (await import('express')).default;
  // @ts-expect-error compression ships no type declarations
  const compression = (await import('compression')).default;
  const initHttpMaps = (await import('../../../src/http/httpMaps')).default;

  const app = express();
  app.use(compression({
    filter: (req: unknown, res: any) => res.getHeader('Content-Type') !== 'text/event-stream'
      && compression.filter(req, res),
  }));
  initHttpMaps(app, { tilesPath: TILES_FILE, countriesPath: COUNTRIES_FILE });

  server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  origin = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

const get = (path: string, headers: Record<string, string> = {}) => {
  return fetch(`${origin}${path}`, { headers });
};

describe('countries boundaries route', () => {
  it('should serve gzipped JSON to a client advertising gzip', async () => {
    const response = await get('/maps/countries.json', { 'accept-encoding': 'gzip' });
    expect(response.status).toEqual(200);
    expect(response.headers.get('content-type')).toMatch(/^application\/json/);
    expect(response.headers.get('vary')).toMatch(/accept-encoding/i);
    expect(response.headers.get('etag')).toMatch(/^"bundled-/);
    expect(response.headers.get('cache-control')).toEqual('public, max-age=300');
    const collection = await response.json() as TestCollection;
    expect(collection.type).toEqual('FeatureCollection');
    expect(collection.features.map((f) => f.properties.ISO3)).toEqual(['FRA', 'DEU']);
  });

  it('should serve plain JSON to a client not advertising gzip', async () => {
    const response = await get('/maps/countries.json', { 'accept-encoding': 'identity' });
    expect(response.status).toEqual(200);
    expect(response.headers.get('content-encoding')).toBeNull();
    expect(response.headers.get('vary')).toMatch(/accept-encoding/i);
    const collection = await response.json() as TestCollection;
    expect(collection.features.length).toEqual(2);
  });

  it('should serve plain JSON when the client refuses gzip with q=0', async () => {
    const response = await get('/maps/countries.json', { 'accept-encoding': 'deflate, gzip;q=0' });
    expect(response.status).toEqual(200);
    expect(response.headers.get('content-encoding')).not.toEqual('gzip');
    const collection = await response.json() as TestCollection;
    expect(collection.features.length).toEqual(2);
  });

  it('should serve gzip to a client accepting any encoding', async () => {
    const response = await get('/maps/countries.json', { 'accept-encoding': '*' });
    expect(response.status).toEqual(200);
    expect(response.headers.get('content-encoding')).toEqual('gzip');
    await response.arrayBuffer();
  });

  it('should answer 304 with the same validator as the 200 it replaces', async () => {
    const first = await get('/maps/countries.json', { 'accept-encoding': 'gzip' });
    const etag = first.headers.get('etag') as string;
    await first.arrayBuffer();

    const second = await get('/maps/countries.json', { 'accept-encoding': 'gzip', 'if-none-match': etag });
    expect(second.status).toEqual(304);
    expect(second.headers.get('etag')).toEqual(etag);
    expect(second.headers.get('cache-control')).toEqual(first.headers.get('cache-control'));
    expect(second.headers.get('vary')).toMatch(/accept-encoding/i);
  });

  it('should serve the body again when the validator does not match', async () => {
    const response = await get('/maps/countries.json', { 'if-none-match': '"bundled-stale"' });
    expect(response.status).toEqual(200);
    const collection = await response.json() as TestCollection;
    expect(collection.features.length).toEqual(2);
  });

  it('should derive the etag from the content and not from its size', async () => {
    const response = await get('/maps/countries.json');
    const etag = response.headers.get('etag') as string;
    await response.arrayBuffer();
    const { gzipSync } = await import('node:zlib');
    const { readFile } = await import('node:fs/promises');
    const { createHash } = await import('node:crypto');
    const expected = createHash('sha256')
      .update(gzipSync(await readFile(COUNTRIES_FILE)))
      .digest('hex')
      .slice(0, 32);
    expect(etag).toEqual(`"bundled-${expected}"`);
  });

  it('should send the bundled validator when the custom file disappears before it is read', async () => {
    const storage = await import('../../../src/database/raw-file-storage');
    vi.mocked(storage.getFileMetadata).mockResolvedValueOnce({ etag: '"custom-etag"', contentLength: 10 });
    const response = await get('/maps/countries.json');
    const collection = await response.json() as TestCollection;
    expect(response.headers.get('etag')).toMatch(/^"bundled-/);
    expect(collection.features.length).toBeGreaterThan(0);
  });

  it('should not let a cache keep a failed response', async () => {
    const storage = await import('../../../src/database/raw-file-storage');
    vi.mocked(storage.getFileMetadata).mockResolvedValueOnce({ etag: '"custom-etag"', contentLength: 10 });
    vi.mocked(storage.downloadFile).mockRejectedValueOnce(new Error('storage unavailable'));
    const response = await get('/maps/countries.json');
    await response.arrayBuffer();
    expect(response.status).toEqual(503);
    expect(response.headers.get('cache-control')).toBeNull();
  });
});

describe('map tiles route', () => {
  it('should serve the bundled tiles without re-encoding them', async () => {
    const response = await get('/maps/world.pmtiles', { 'accept-encoding': 'gzip' });
    expect(response.status).toEqual(200);
    expect(response.headers.get('content-type')).toEqual('application/octet-stream');
    expect(response.headers.get('accept-ranges')).toEqual('bytes');
    expect(response.headers.get('cache-control')).toMatch(/no-transform/);
    expect(response.headers.get('cache-control')).toMatch(/max-age=300\b/);
    expect(response.headers.get('content-encoding')).toBeNull();
    const body = Buffer.from(await response.arrayBuffer());
    expect(body.subarray(0, 7).toString()).toEqual('PMTiles');
  });

  it('should honour a range request', async () => {
    const response = await get('/maps/world.pmtiles', { range: 'bytes=0-9' });
    expect(response.status).toEqual(206);
    expect(response.headers.get('content-range')).toMatch(/^bytes 0-9\//);
    const body = Buffer.from(await response.arrayBuffer());
    expect(body.length).toEqual(10);
  });

  it('should answer 304 with the same validator as the 200 it replaces', async () => {
    const first = await get('/maps/world.pmtiles');
    const etag = first.headers.get('etag') as string;
    await first.arrayBuffer();
    expect(etag).toMatch(/^"bundled-/);

    const second = await get('/maps/world.pmtiles', { 'if-none-match': etag });
    expect(second.status).toEqual(304);
    expect(second.headers.get('etag')).toEqual(etag);
    expect(second.headers.get('cache-control')).toEqual(first.headers.get('cache-control'));
  });

  it('should report an unsatisfiable range', async () => {
    const full = await get('/maps/world.pmtiles');
    const totalSize = Number(full.headers.get('content-length'));
    await full.arrayBuffer();

    const response = await get('/maps/world.pmtiles', { range: `bytes=${totalSize + 100}-${totalSize + 200}` });
    expect(response.status).toEqual(416);
    expect(response.headers.get('content-range')).toEqual(`bytes */${totalSize}`);
  });
});
