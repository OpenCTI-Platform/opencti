import { convertIdentityToStix } from '../../database/stix-2-1-converter';
import type { StixOrganization, StoreEntityOrganization } from './organization-types';

const convertOrganizationToStix = (instance: StoreEntityOrganization): StixOrganization => {
  return convertIdentityToStix(instance, instance.entity_type);
};

export default convertOrganizationToStix;
