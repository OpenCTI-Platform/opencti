import { convertIdentityToStix } from '../../database/stix-2-1-converter';
import { convertIdentityToStix as convertIdentityToStix_2_0 } from '../../database/stix-2-0-converter';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM } from './securityPlatform-types';
import type { Stix2SecurityPlatform, StixSecurityPlatform, StoreEntitySecurityPlatform } from './securityPlatform-types';
import type { StoreEntity } from '../../types/store';
import { assertType } from '../../database/stix-converter-utils';

const convertSecurityPlatformToStix = (instance: StoreEntitySecurityPlatform): StixSecurityPlatform => {
  return convertIdentityToStix(instance, instance.entity_type);
};

export const convertSecurityPlatformToStix_2_0 = (instance: StoreEntity): Stix2SecurityPlatform => {
  assertType(ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, instance.entity_type);
  const securityPlatform = instance as StoreEntitySecurityPlatform;
  return {
    ...convertIdentityToStix_2_0(instance, instance.entity_type),
    security_platform_type: securityPlatform.security_platform_type,
  };
};

export default convertSecurityPlatformToStix;
