import { computeAccountStatusChoices } from '../../config/conf';
import { draftChange, draftContext } from '../../schema/attribute-definition';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { registerDefinition, type ModuleDefinition } from '../../schema/module';
import { objectOrganization } from '../../schema/stixRefRelationship';
import { normalizeEmail } from '../../utils/email';
import convertUserToStix from './user-converter';
import { apiTokens, ENTITY_TYPE_USER, type StixUser, type StoreEntityUser } from './user-types';

const USER_DEFINITION: ModuleDefinition<StoreEntityUser, StixUser> = {
  type: {
    id: 'user',
    name: ENTITY_TYPE_USER,
    category: ABSTRACT_INTERNAL_OBJECT,
    aliased: false,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_USER]: [{ src: 'user_email' }],
    },
    resolvers: {
      user_email(data: string) {
        return normalizeEmail(data);
      },
    },
  },
  attributes: [
    { name: 'user_email', label: 'Email', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'personal_notifiers', label: 'Trigger for personal notifiers', type: 'string', format: 'short', mandatoryType: 'internal', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'password', label: 'Password', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // { name: 'password', label: 'Password', type: 'string', format: 'short', mandatoryType: 'external', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    // bcrypt hashes of the previous passwords, newest first; never exposed through the API
    { name: 'password_history', label: 'Password history', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'firstname', label: 'User firstname', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'lastname', label: 'User lastname', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'theme', label: 'Theme', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'language', label: 'Language', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'external', label: 'External', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    {
      name: 'bookmarks',
      label: 'Bookmarks',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: true,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'id', label: 'Id', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
        { name: 'type', label: 'Type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'no', multiple: false, upsert: true, isFilterable: true },
      ],
    },
    apiTokens,
    { name: 'otp_secret', label: 'OTP secret', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'otp_qr', label: 'OTP QR', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'otp_activated', label: '2FA state', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'password_valid_until', label: 'Password valid until', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'default_dashboard', label: 'Default dashboard', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { ...draftContext, isFilterable: false },
    { ...draftChange, isFilterable: false },
    { name: 'default_time_field', label: 'Default time field', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'account_status', label: 'Account status', type: 'string', format: 'enum', values: Object.keys(computeAccountStatusChoices()), mandatoryType: 'external', editDefault: true, multiple: false, upsert: false, isFilterable: true },
    { name: 'account_lock_after_date', label: 'User account expiration date', type: 'date', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'merged_into', label: 'Merged into', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
    { name: 'administrated_organizations', label: 'Administrated organizations', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'unit_system', label: 'Unit system', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'submenu_show_icons', label: 'Show submenu icons', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'submenu_auto_collapse', label: 'Auto collapse submenus', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'monochrome_labels', label: 'Monochrome labels and entity types', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: false },
    { name: 'unsubscribed_news_feed_types', label: 'Unsubscribed news feed types', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: true, upsert: false, isFilterable: false },
    {
      name: 'user_confidence_level',
      label: 'User Confidence Level',
      type: 'object',
      format: 'standard',
      mandatoryType: 'no',
      editDefault: false,
      multiple: false,
      upsert: false,
      isFilterable: false,
      mappings: [
        { name: 'max_confidence', label: 'Max Confidence', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'no', multiple: false, upsert: false, isFilterable: true },
        {
          name: 'overrides',
          label: 'Overrides',
          type: 'object',
          format: 'nested',
          editDefault: false,
          mandatoryType: 'internal',
          multiple: true,
          upsert: true,
          isFilterable: false,
          mappings: [
            { name: 'entity_type', label: 'Entity Type', type: 'string', format: 'short', editDefault: false, mandatoryType: 'external', multiple: false, upsert: false, isFilterable: true },
            { name: 'max_confidence', label: 'Max Confidence', type: 'numeric', precision: 'integer', editDefault: false, mandatoryType: 'external', multiple: false, upsert: false, isFilterable: true },
          ],
        },
      ],
    },
    { name: 'user_service_account', label: 'User service account', type: 'boolean', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
  ],
  relations: [],
  relationsRefs: [{ ...objectOrganization, isFilterable: false }],
  representative: (stix: StixUser) => {
    return stix.name ?? 'undefined';
  },
  converter_2_1: convertUserToStix,
};

registerDefinition(USER_DEFINITION);
