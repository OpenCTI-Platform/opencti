import type { CatalogContractDtoV0 } from '../catalog-types';

export type CatalogSyncSourceConfig = {
  kind: 'embedded';
  uri: 'embedded';
} | {
  kind: 'local';
  filepath: string;
  uri: string;
};

export type CatalogContractSyncSource = CatalogContractDtoV0 & {
  id: string; // slug-version
};

export interface CatalogSyncSource {
  id: string;
  name: string;
  description: string;
  version: string;
  contracts: Array<CatalogContractSyncSource>;
}
