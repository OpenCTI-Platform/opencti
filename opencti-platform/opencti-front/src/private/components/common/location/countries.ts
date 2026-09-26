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

const fetchCountries = async (): Promise<CountriesCollection> => {
  try {
    const response = await fetch(`${APP_BASE_PATH}/maps/countries.json`);
    if (!response.ok) {
      throw new Error(`Unable to load country boundaries (${response.status})`);
    }
    const collection = await response.json();
    return collection as CountriesCollection;
  } catch (error) {
    pending = null;
    throw error;
  }
};

export const loadCountries = (): Promise<CountriesCollection> => {
  pending ??= fetchCountries();
  return pending;
};

// The endpoint serves a different file once an administrator uploads or deletes a custom one,
// and the memoised promise would otherwise keep the previous boundaries for the rest of the
// session.
export const invalidateCountries = () => {
  pending = null;
};
