import type { BasicStoreEntityEmailTemplate } from '../../../../src/modules/emailTemplate/emailTemplate-types';

export const customEmailTemplate = {
  id: 'custom-email-template-id',
  internal_id: 'custom-email-template-id',
  standard_id: 'emailtemplate--5d2c1a7e-3b4f-4c6d-8e9f-0a1b2c3d4e5f',
  entity_type: 'EmailTemplate',
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  name: 'Welcome analyst',
  description: 'Onboarding message for new analysts',
  email_object: 'Welcome to OpenCTI',
  sender_email: 'CTI team',
  template_body: '<p>Hello $user.firstname</p>',
} as unknown as BasicStoreEntityEmailTemplate;

export const otherEmailTemplate = {
  ...customEmailTemplate,
  id: 'other-email-template-id',
  internal_id: 'other-email-template-id',
  standard_id: 'emailtemplate--9a8b7c6d-5e4f-4a3b-9c2d-1e0f9a8b7c6d',
  name: 'Built-In Template For Onboarding',
  description: 'Default email template to onboard new users',
  email_object: 'Welcome',
  template_body: '<p>Welcome</p>',
} as unknown as BasicStoreEntityEmailTemplate;

export const ALL_EMAIL_TEMPLATES = [customEmailTemplate, otherEmailTemplate];
