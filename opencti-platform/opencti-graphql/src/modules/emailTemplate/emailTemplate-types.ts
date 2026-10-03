import type { BasicStoreEntity, StoreEntity } from '../../types/store';

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
