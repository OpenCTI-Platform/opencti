import type { Geometry } from 'geojson';
import { APP_BASE_PATH } from '../../../../relay/environment';

export interface CountryProperties {
  ISO2: string;
  ISO3: string;
  NAME: string;
  LON: number;
  LAT: number;
}

export interface CountriesCollection {
  type: 'FeatureCollection';
  features: Array<{
    type: 'Feature';
    properties: CountryProperties;
    geometry: Geometry;
  }>;
}

let pending: Promise<CountriesCollection> | null = null;
let bypassHttpCache = false;
let generation = 0;

const fetchCountries = async (): Promise<CountriesCollection> => {
  const requestGeneration = generation;
  const reload = bypassHttpCache;
  bypassHttpCache = false;
  try {
    const response = await fetch(`${APP_BASE_PATH}/maps/countries.json`, reload ? { cache: 'reload' } : undefined);
    if (!response.ok) {
      throw new Error(`Unable to load country boundaries (${response.status})`);
    }
    const collection = await response.json();
    return collection as CountriesCollection;
  } catch (error) {
    if (requestGeneration === generation) {
      pending = null;
      bypassHttpCache ||= reload;
    }
    throw error;
  }
};

export const loadCountries = (): Promise<CountriesCollection> => {
  pending ??= fetchCountries();
  return pending;
};

export const invalidateCountries = () => {
  generation += 1;
  pending = null;
  bypassHttpCache = true;
};
