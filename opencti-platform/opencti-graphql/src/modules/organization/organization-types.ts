import type { BasicIdentityEntity, StoreEntityIdentity } from '../../types/store';
import type { StixIdentity } from '../../types/stix-sdo';
import { RELATION_PARTICIPATE_TO } from '../../schema/internalRelationship';

export const ENTITY_TYPE_IDENTITY_ORGANIZATION = 'Organization';

// region Database types
export interface BasicStoreEntityOrganization extends BasicIdentityEntity {
  x_opencti_organization_type: string
  x_opencti_reliability: string
  sectors: string[]
  default_dashboard: string
  authorized_authorities: string[]
  grantable_groups: string[]
  [RELATION_PARTICIPATE_TO]: string[]
}

export interface StoreEntityOrganization extends StoreEntityIdentity, BasicStoreEntityOrganization {}
// endregion

// region Stix type
export type StixOrganization = StixIdentity;
// endregion
