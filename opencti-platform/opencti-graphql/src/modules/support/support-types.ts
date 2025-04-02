import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_SUPPORT_PACKAGE = 'Support-Package';
export const SUPPORT_BUS = 'SupportBus';
export interface BasicStoreEntitySupportPackage extends BasicStoreEntity {
  name: string
  package_status: string
  package_url: string
  package_upload_dir: string
  nodes_count: number
}

export interface StoreEntitySupportPackage extends StoreEntity {
  name: string
  package_status: string
  package_url: string
  package_upload_dir: string
  nodes_count: number
}

export interface StixSupportPackage extends StixObject {
  name: string
  package_status: string
  package_url: string
  package_upload_dir: string
  nodes_count: number
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
