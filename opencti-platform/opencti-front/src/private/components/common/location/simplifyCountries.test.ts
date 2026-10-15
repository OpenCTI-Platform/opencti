import { describe, expect, it } from 'vitest';
import type { Position } from 'geojson';
import { simplifyCountries, simplifyRing } from './simplifyCountries';
import type { CountriesCollection } from './countries';

const VATICAN_RING: Position[] = [
  [12.45313691700008, 41.90275194100009],
  [12.452714082000085, 41.903016213000015],
  [12.452766936000103, 41.903439049],
  [12.45303120800014, 41.903914738000125],
  [12.453982588000144, 41.903861883999994],
  [12.454035442000077, 41.90275194100009],
  [12.45313691700008, 41.90275194100009],
];

const LARGE_RING: Position[] = [
  ...Array.from({ length: 100 }, (_, index): Position => [index / 10, 0]),
  [10, 10],
  [0, 10],
  [0, 0],
];

describe('simplifyCountries', () => {
  it('keeps the original ring of a country too small to survive simplification', () => {
    expect(simplifyRing(VATICAN_RING)).toEqual(VATICAN_RING);
  });

  it('simplifies the rings of larger countries', () => {
    const simplified = simplifyRing(LARGE_RING);
    expect(simplified.length).toBeGreaterThanOrEqual(4);
    expect(simplified.length).toBeLessThan(LARGE_RING.length);
  });

  it('keeps small countries drawable in a simplified collection', () => {
    const collection: CountriesCollection = {
      type: 'FeatureCollection',
      features: [{
        type: 'Feature',
        properties: { ISO2: 'VA', ISO3: 'VAT', NAME: 'Vatican', LON: 12.45, LAT: 41.9 },
        geometry: { type: 'Polygon', coordinates: [VATICAN_RING] },
      }],
    };
    const [feature] = simplifyCountries(collection).features;
    expect(feature.geometry).toEqual({ type: 'Polygon', coordinates: [VATICAN_RING] });
  });
});
