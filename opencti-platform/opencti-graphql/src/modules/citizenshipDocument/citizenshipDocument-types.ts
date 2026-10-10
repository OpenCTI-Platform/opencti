import type { BasicIdentityEntity, StoreEntityIdentity } from '../../types/store';
import type { StixIdentity } from '../../types/stix-2-1-sdo';
import type { StixIdentity as StixIdentity2 } from '../../types/stix-2-0-sdo';

export const ENTITY_TYPE_IDENTITY_CITIZENSHIP_DOCUMENT = 'Citizenship-Document';

// region Database types
export interface BasicStoreEntityCitizenshipDocument extends BasicIdentityEntity {
  citizenship_document_type: string;
}

export interface StoreEntityCitizenshipDocument extends StoreEntityIdentity, BasicStoreEntityCitizenshipDocument {}
// endregion

// region Stix type
export type StixCitizenshipDocument = StixIdentity;
// endregion

// region Stix 2.0 type
export interface Stix2CitizenshipDocument extends StixIdentity2 {
  citizenship_document_type: string;
}
// endregion
