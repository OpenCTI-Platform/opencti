import { convertIdentityToStix } from '../../database/stix-converter';
import type { StixOrganization, StoreEntityOrganization } from './organization-types';

const convertOrganizationToStix = (instance: StoreEntityOrganization): StixOrganization => {
  return convertIdentityToStix(instance, instance.entity_type);
};

export default convertOrganizationToStix;
