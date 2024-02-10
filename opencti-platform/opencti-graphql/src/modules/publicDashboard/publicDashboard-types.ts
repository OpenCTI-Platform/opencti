import type { BasicStoreEntity, StoreEntity, StoreMarkingDefinition } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { AuthorizedMember } from '../../utils/access';

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
  authorized_members: Array<AuthorizedMember>;
  allowed_markings_ids: Array<string>;
  allowed_markings: Array<StoreMarkingDefinition>;
}

export interface StoreEntityPublicDashboard extends StoreEntity {
  name: string;
  description: string;
  dashboard_id: string;
  user_id: string;
  public_manifest: string;
  private_manifest: string;
  uri_key: string;
  authorized_members: Array<AuthorizedMember>;
  allowed_markings_ids: Array<string>;
  allowed_markings: Array<StoreMarkingDefinition>;
}
// endregion

// region cache type
export interface PublicDashboardCached {
  id: string;
  internal_id: string;
  uri_key: string;
  dashboard_id: string;
  private_manifest: { widgets:any, parameters: any };
  user_id: string;
  allowed_markings_ids: string[];
  allowed_markings: Array<StoreMarkingDefinition>;
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
  allowed_markings_ids: Array<string>;
  allowed_markings: Array<StoreMarkingDefinition>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
