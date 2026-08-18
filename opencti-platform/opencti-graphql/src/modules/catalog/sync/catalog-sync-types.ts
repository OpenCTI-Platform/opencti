import type { CatalogContract } from '../catalog-types';

export type CatalogSyncSourceConfig = {
  kind: 'embedded';
  uri: 'embedded';
} | {
  kind: 'local';
  filepath: string;
  uri: string;
} | {
  kind: 'remote';
  uri: string;
};

export type CatalogContractSyncSource = CatalogContract & {
  id: string; // slug-version
};

export interface CatalogSyncSource {
  id: string;
  name: string;
  description: string;
  version: string;
  contracts: Array<CatalogContractSyncSource>;
}
