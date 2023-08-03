import type { BasicIdentityEntity, StoreEntityIdentity } from '../../types/store';
import type { OrganizationReliability } from '../../types/stix-common';
import type { StixIdentity } from '../../types/stix-sdo';

export const ENTITY_TYPE_IDENTITY_ORGANIZATION = 'Organization';

// region Database types
export interface BasicStoreEntityOrganization extends BasicIdentityEntity {
  x_opencti_organization_type: string
  x_opencti_reliability: OrganizationReliability
  sectors: string[]
  default_dashboard: string
}

export interface StoreEntityOrganization extends StoreEntityIdentity, BasicStoreEntityOrganization { }
// endregion

// region Stix type
export type StixOrganization = StixIdentity;
// endregion
