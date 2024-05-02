import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { SupportNodeStatus } from '../../generated/graphql';

export const ENTITY_TYPE_SUPPORT_PACKAGE = 'Support-Package';
export const SUPPORT_BUS = 'SupportBus';
export interface BasicStoreEntitySupportPackage extends BasicStoreEntity {
  name: string
  package_status: string
  package_url: string
  package_upload_dir: string
  nodes_status: Array<SupportNodeStatus>
  nodes_count: number
}

export interface StoreEntitySupportPackage extends StoreEntity {
  name: string
  package_status: string
  package_url: string
  package_upload_dir: string
  nodes_status: Array<SupportNodeStatus>
  nodes_count: number
}

export interface StixSupportPackage extends StixObject {
  name: string
  package_status: string
  package_url: string
  package_upload_dir: string
  nodes_status: Array<SupportNodeStatus>
  nodes_count: number
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
