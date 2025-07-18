import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_EMAIL_TEMPLATE = 'EmailTemplate';

export interface BasicStoreEntityEmailTemplate extends BasicStoreEntity {
  name: string;
  description: string;
  email_object: string;
  sender_email: string;
  template_body: string;
}

export interface StoreEntityEmailTemplate extends StoreEntity {
  name: string;
  description: string;
  email_object: string;
  sender_email: string;
  template_body: string;
}

export interface StixEmailTemplate extends StixObject {
  name: string;
  description: string;
  email_object: string;
  sender_email: string;
  template_body: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  };
}
