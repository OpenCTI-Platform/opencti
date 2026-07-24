import data from './countries.json';

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
    geometry: object;
  }>;
}

export default data as unknown as CountriesCollection;
