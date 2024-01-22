import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_PUBLIC_DASHBOARD = 'PublicDashboard';

// region Database types
export interface BasicStoreEntityPublicDashboard extends BasicStoreEntity {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
}

export interface StoreEntityPublicDashboard extends StoreEntity {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
}
// endregion

// region Stix type
export interface StixPublicDashboard extends StixDomainObject {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
