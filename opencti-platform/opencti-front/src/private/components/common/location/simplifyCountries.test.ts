import { describe, expect, it } from 'vitest';
import type { Position } from 'geojson';
import { simplifyCountries } from './simplifyCountries';
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

const collectionOf = (...countries: [string, Position[]][]): CountriesCollection => ({
  type: 'FeatureCollection',
  features: countries.map(([iso3, ring]) => ({
    type: 'Feature',
    properties: { ISO2: iso3.slice(0, 2), ISO3: iso3, NAME: iso3, LON: ring[0][0], LAT: ring[0][1] },
    geometry: { type: 'Polygon', coordinates: [ring] },
  })),
});

const ringOf = (collection: CountriesCollection, index: number) => {
  const { geometry } = collection.features[index];
  return geometry.type === 'Polygon' ? geometry.coordinates[0] : [];
};

const keys = (positions: Position[]) => new Set(positions.map(([lon, lat]) => `${lon.toFixed(9)},${lat.toFixed(9)}`));

const WEST: Position[] = [[0, 0], [10, 0], [10, 5], [10, 10], [0, 10], [0, 0]];
const EAST: Position[] = [[10, 0], [20, 0], [20, 10], [10, 10], [10, 5], [10, 0]];

describe('simplifyCountries', () => {
  it('keeps the original ring of a country too small to survive simplification', () => {
    const { countries } = simplifyCountries(collectionOf(['VAT', VATICAN_RING]));
    expect(keys(ringOf(countries, 0))).toEqual(keys(VATICAN_RING));
  });

  it('simplifies the rings of larger countries', () => {
    const bottom = Array.from({ length: 100 }, (_, index): Position => [index / 10, 0]);
    const ring: Position[] = [...bottom, [10, 10], [0, 10], [0, 0]];
    const { countries } = simplifyCountries(collectionOf(['BIG', ring]));
    expect(ringOf(countries, 0).length).toBeLessThan(ring.length);
  });

  it('returns the land border shared by two countries, without their coastlines', () => {
    const { borders } = simplifyCountries(collectionOf(['WST', WEST], ['EST', EAST]));
    expect(borders).toHaveLength(1);
    const [border] = borders;
    expect(border.every(([lon]) => Math.abs(lon - 10) < 1e-9)).toBe(true);
    expect(keys([border[0], border[border.length - 1]])).toEqual(keys([[10, 0], [10, 10]]));
  });

  it('simplifies a shared border identically on both sides', () => {
    const { countries } = simplifyCountries(collectionOf(['WST', WEST], ['EST', EAST]));
    const onBorder = (ring: Position[]) => keys(ring.filter(([lon]) => Math.abs(lon - 10) < 1e-9));
    expect(onBorder(ringOf(countries, 0))).toEqual(onBorder(ringOf(countries, 1)));
  });
});
