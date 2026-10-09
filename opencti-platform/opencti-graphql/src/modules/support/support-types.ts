import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_SUPPORT_PACKAGE = 'Support-Package';
export const SUPPORT_BUS = 'SupportBus';
export interface BasicStoreEntitySupportPackage extends BasicStoreEntity {
  name: string;
  package_status: string;
  package_url: string;
  package_upload_dir: string;
  nodes_count: number;
}

export interface StoreEntitySupportPackage extends StoreEntity {
  name: string;
  package_status: string;
  package_url: string;
  package_upload_dir: string;
  nodes_count: number;
}
