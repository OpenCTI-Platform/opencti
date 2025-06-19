import { convertIdentityToStix } from '../../database/stix-2-1-converter';
import type { StixSecurityPlatform, StoreEntitySecurityPlatform } from './securityPlatform-types';

const convertSecurityPlatformToStix = (instance: StoreEntitySecurityPlatform): StixSecurityPlatform => {
  return convertIdentityToStix(instance, instance.entity_type);
};

export default convertSecurityPlatformToStix;
