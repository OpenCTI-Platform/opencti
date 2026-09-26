import { describe, expect, it } from 'vitest';
import { gzipSync } from 'node:zlib';
import { decodeCountriesFile } from '../../../src/domain/settings';

const collection = (features: unknown[]) => JSON.stringify({ type: 'FeatureCollection', features });

const feature = (properties: Record<string, unknown>) => ({
  type: 'Feature',
  properties,
  geometry: { type: 'Polygon', coordinates: [[[0, 0], [1, 0], [1, 1], [0, 0]]] },
});

const valid = collection([
  feature({ ISO3: 'FRA', ISO2: 'FR', NAME: 'France', LON: 2.5, LAT: 46.5 }),
  feature({ ISO3: 'DEU', ISO2: 'DE', NAME: 'Germany', LON: 10.5, LAT: 51 }),
]);

describe('decodeCountriesFile', () => {
  it('should accept plain GeoJSON and return it uncompressed', async () => {
    const decoded = await decodeCountriesFile(Buffer.from(valid));
    expect(JSON.parse(decoded.toString('utf8')).features.length).toEqual(2);
  });

  it('should accept gzipped GeoJSON, detected by its magic bytes', async () => {
    const compressed = gzipSync(Buffer.from(valid));
    expect(compressed[0]).toEqual(0x1f);
    expect(compressed[1]).toEqual(0x8b);
    const decoded = await decodeCountriesFile(compressed);
    expect(JSON.parse(decoded.toString('utf8')).features.length).toEqual(2);
  });

  it('should reject a corrupt gzip archive as a validation error', async () => {
    const corrupt = Buffer.concat([Buffer.from([0x1f, 0x8b]), Buffer.from('not actually gzip')]);
    await expect(decodeCountriesFile(corrupt)).rejects.toThrow(/not a readable gzip archive/);
  });

  it('should reject content that is not JSON', async () => {
    await expect(decodeCountriesFile(Buffer.from('PMTilesnot json at all')))
      .rejects.toThrow(/not valid JSON/);
  });

  it('should reject JSON that is not a FeatureCollection', async () => {
    await expect(decodeCountriesFile(Buffer.from(JSON.stringify({ type: 'Feature', features: [] }))))
      .rejects.toThrow(/FeatureCollection/);
  });

  it('should reject a FeatureCollection without any feature', async () => {
    await expect(decodeCountriesFile(Buffer.from(collection([]))))
      .rejects.toThrow(/at least one feature/);
  });

  it('should reject a feature missing its ISO3 property', async () => {
    const missing = collection([feature({ ISO2: 'FR', NAME: 'France' })]);
    await expect(decodeCountriesFile(Buffer.from(missing))).rejects.toThrow(/ISO3/);
  });

  it('should reject a feature whose ISO3 is empty', async () => {
    const empty = collection([feature({ ISO3: '', NAME: 'Nowhere' })]);
    await expect(decodeCountriesFile(Buffer.from(empty))).rejects.toThrow(/ISO3/);
  });
});
