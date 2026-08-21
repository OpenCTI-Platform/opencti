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
  product_version: string;
  manifest_version: string | null;
  manifest_schema_version: '0' | '1';
  contracts: Array<CatalogContractSyncSource>;
}
