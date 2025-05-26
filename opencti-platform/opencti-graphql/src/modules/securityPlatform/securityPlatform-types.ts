import type { BasicIdentityEntity, StoreEntityIdentity } from '../../types/store';
import type { StixIdentity } from '../../types/stix-2-1-sdo';

export const ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM = 'SecurityPlatform';

// region Database types
export interface BasicStoreEntitySecurityPlatform extends BasicIdentityEntity {
  security_platform_type: string
}

export interface StoreEntitySecurityPlatform extends StoreEntityIdentity, BasicStoreEntitySecurityPlatform {}
// endregion

// region Stix type
export type StixSecurityPlatform = StixIdentity;
// endregion
