import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsAdminWithError, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { patchAttribute } from '../../../../src/database/middleware';
import { ENTITY_TYPE_SETTINGS } from '../../../../src/schema/internalObject';

const SMTP_CONFIGURATION_QUERY = gql`
  query SmtpConfigurationTest {
    smtpConfiguration {
      smtp_enabled
      use_db_config
      sender_email_address
      hostname
      port
      use_ssl
      reject_unauthorized
      auth_type
      username
      oauth_user
      oauth_client_id
      oauth_issuer
    }
  }
`;

const SMTP_CONFIGURATION_EDIT_MUTATION = gql`
  mutation SmtpConfigurationEditTest($input: SmtpConfigurationAddInput!) {
    smtpConfigurationEdit(input: $input) {
      smtp_enabled
      use_db_config
      hostname
      port
      auth_type
    }
  }
`;

const SMTP_CONFIGURATION_TEST_MUTATION = gql`
  mutation SmtpConfigurationTestMutation($email: String!) {
    smtpConfigurationTest(email: $email)
  }
`;

const clearSmtpConfiguration = async () => {
  // Retrieve settings id via a raw query to reset smtp_configuration between tests
  const { data } = await queryAsAdminWithSuccess({ query: gql`query { settings { id } }` });
  const settingsId = data?.settings?.id;
  if (settingsId) {
    await patchAttribute(testContext, ADMIN_USER, settingsId, ENTITY_TYPE_SETTINGS, { smtp_configuration: null });
  }
};

describe('SmtpConfiguration resolvers', () => {
  beforeAll(clearSmtpConfiguration);
  afterAll(clearSmtpConfiguration);

  describe('Query smtpConfiguration', () => {
    it('should return null when no configuration has been set in settings', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_QUERY });
      expect(result.data.smtpConfiguration).toBeNull();
    });

    it('should be forbidden for users without SETTINGS_SETACCESSES capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: SMTP_CONFIGURATION_QUERY });
    });
  });

  describe('Mutation smtpConfigurationEdit', () => {
    it('should reject port 25', async () => {
      await queryAsAdminWithError(
        { query: SMTP_CONFIGURATION_EDIT_MUTATION, variables: { input: { smtp_enabled: false, use_db_config: false, port: 25 } } },
        'Port 25 is not allowed for SMTP configuration',
      );
    });

    it('should save smtp configuration to settings', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SMTP_CONFIGURATION_EDIT_MUTATION,
        variables: { input: { smtp_enabled: false, use_db_config: true, hostname: 'smtp.example.com', port: 587 } },
      });
      expect(result.data.smtpConfigurationEdit.hostname).toBe('smtp.example.com');
      expect(result.data.smtpConfigurationEdit.smtp_enabled).toBe(false);
      expect(result.data.smtpConfigurationEdit.use_db_config).toBe(true);
    });

    it('should be queryable after edit', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_QUERY });
      expect(result.data.smtpConfiguration).not.toBeNull();
      expect(result.data.smtpConfiguration.hostname).toBe('smtp.example.com');
    });

    it('should update existing configuration (upsert)', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SMTP_CONFIGURATION_EDIT_MUTATION,
        variables: { input: { smtp_enabled: true, use_db_config: true, hostname: 'smtp-updated.example.com', port: 587 } },
      });
      expect(result.data.smtpConfigurationEdit.smtp_enabled).toBe(true);
      expect(result.data.smtpConfigurationEdit.hostname).toBe('smtp-updated.example.com');
    });
  });

  describe('SmtpConfiguration secrets are not exposed', () => {
    it('should not include secret fields in the query response', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_QUERY });
      const config = result.data.smtpConfiguration;
      expect(config).not.toHaveProperty('password');
      expect(config).not.toHaveProperty('oauth_client_secret');
      expect(config).not.toHaveProperty('oauth_access_token');
      expect(config).not.toHaveProperty('oauth_refresh_token');
    });
  });

  describe('Mutation smtpConfigurationTest', () => {
    it('should attempt to connect and fail with a network error when no SMTP server is available', async () => {
      await queryAsAdminWithError(
        { query: SMTP_CONFIGURATION_TEST_MUTATION, variables: { email: 'test@example.com' } },
      );
    });
  });
});

