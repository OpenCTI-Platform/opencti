import { convertIdentityToStix } from '../../database/stix-2-1-converter';
import { convertIdentityToStix as convertIdentityToStix_2_0 } from '../../database/stix-2-0-converter';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from './organization-types';
import type { Stix2Organization, StixOrganization, StoreEntityOrganization } from './organization-types';
import type { StoreEntity } from '../../types/store';
import { assertType } from '../../database/stix-converter-utils';

const convertOrganizationToStix = (instance: StoreEntityOrganization): StixOrganization => {
  return convertIdentityToStix(instance, instance.entity_type);
};

export const convertOrganizationToStix_2_0 = (instance: StoreEntity): Stix2Organization => {
  assertType(ENTITY_TYPE_IDENTITY_ORGANIZATION, instance.entity_type);
  return convertIdentityToStix_2_0(instance, instance.entity_type);
};

export default convertOrganizationToStix;
