import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { deleteElementById } from '../../../../src/database/middleware';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../../utils/testQuery';
import { queryAsAdminWithSuccess, queryAsAdminWithError, queryAsUserIsExpectedForbidden } from '../../../utils/testQueryHelper';
import { ENTITY_TYPE_SMTP_CONFIGURATION } from '../../../../src/modules/smtpConfiguration/smtpConfiguration-types';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import type { BasicStoreEntitySmtpConfiguration } from '../../../../src/modules/smtpConfiguration/smtpConfiguration-types';

const SMTP_CONFIGURATION_QUERY = gql`
  query SmtpConfigurationTest {
    smtpConfiguration {
      id
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

const SMTP_CONFIGURATION_BY_ID_QUERY = gql`
  query SmtpConfigurationByIdTest($id: ID!) {
    smtpConfigurationById(id: $id) {
      id
      hostname
      smtp_enabled
    }
  }
`;

const SMTP_CONFIGURATION_ADD_MUTATION = gql`
  mutation SmtpConfigurationAddTest($input: SmtpConfigurationAddInput!) {
    smtpConfigurationAdd(input: $input) {
      id
      smtp_enabled
      use_db_config
      hostname
      port
      auth_type
    }
  }
`;

const SMTP_CONFIGURATION_UPDATE_MUTATION = gql`
  mutation SmtpConfigurationUpdateTest($id: ID!, $input: SmtpConfigurationAddInput!) {
    smtpConfigurationUpdate(id: $id, input: $input) {
      id
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

const SMTP_CONFIGURATION_DELETE_MUTATION = gql`
  mutation SmtpConfigurationDeleteTest($id: ID!) {
    smtpConfigurationDelete(id: $id)
  }
`;

describe('SmtpConfiguration resolvers', () => {
  let configId: string;

  beforeAll(async () => {
    // Ensure clean state
    const configs = await fullEntitiesList<BasicStoreEntitySmtpConfiguration>(testContext, ADMIN_USER, [ENTITY_TYPE_SMTP_CONFIGURATION]);
    await Promise.all(configs.map(({ id }) => deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_SMTP_CONFIGURATION)));
  });

  afterAll(async () => {
    const configs = await fullEntitiesList<BasicStoreEntitySmtpConfiguration>(testContext, ADMIN_USER, [ENTITY_TYPE_SMTP_CONFIGURATION]);
    await Promise.all(configs.map(({ id }) => deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_SMTP_CONFIGURATION)));
  });

  describe('Query smtpConfiguration', () => {
    it('should return null when no configuration exists in database', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_QUERY });
      expect(result.data.smtpConfiguration).toBeNull();
    });

    it('should be forbidden for users without SETTINGS_SETACCESSES capability', async () => {
      await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, { query: SMTP_CONFIGURATION_QUERY });
    });
  });

  describe('Mutation smtpConfigurationAdd', () => {
    it('should create a new smtp configuration', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SMTP_CONFIGURATION_ADD_MUTATION,
        variables: { input: { smtp_enabled: false, use_db_config: false, hostname: 'smtp.example.com', port: 587 } },
      });
      expect(result.data.smtpConfigurationAdd.id).toBeDefined();
      expect(result.data.smtpConfigurationAdd.hostname).toBe('smtp.example.com');
      expect(result.data.smtpConfigurationAdd.smtp_enabled).toBe(false);
      configId = result.data.smtpConfigurationAdd.id;
    });

    it('should reject creating a second configuration', async () => {
      await queryAsAdminWithError(
        { query: SMTP_CONFIGURATION_ADD_MUTATION, variables: { input: { smtp_enabled: false, use_db_config: false } } },
        'An SMTP configuration already exists',
      );
    });

    it('should reject port 25 on create', async () => {
      await queryAsAdminWithError(
        { query: SMTP_CONFIGURATION_ADD_MUTATION, variables: { input: { smtp_enabled: false, use_db_config: false, port: 25 } } },
        'Port 25 is not allowed for SMTP configuration',
      );
    });
  });

  describe('Query smtpConfigurationById', () => {
    it('should return the configuration by id', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_BY_ID_QUERY, variables: { id: configId } });
      expect(result.data.smtpConfigurationById.id).toBe(configId);
      expect(result.data.smtpConfigurationById.hostname).toBe('smtp.example.com');
    });

    it('should return null for an unknown id', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_BY_ID_QUERY, variables: { id: '00000000-0000-0000-0000-000000000000' } });
      expect(result.data.smtpConfigurationById).toBeNull();
    });
  });

  describe('Mutation smtpConfigurationUpdate', () => {
    it('should update the configuration by id', async () => {
      const result = await queryAsAdminWithSuccess({
        query: SMTP_CONFIGURATION_UPDATE_MUTATION,
        variables: { id: configId, input: { smtp_enabled: true, hostname: 'smtp-updated.example.com', port: 587, auth_type: 'basic' } },
      });
      expect(result.data.smtpConfigurationUpdate.id).toBe(configId);
      expect(result.data.smtpConfigurationUpdate.smtp_enabled).toBe(true);
      expect(result.data.smtpConfigurationUpdate.hostname).toBe('smtp-updated.example.com');
    });

    it('should reject port 25', async () => {
      await queryAsAdminWithError(
        { query: SMTP_CONFIGURATION_UPDATE_MUTATION, variables: { id: configId, input: { port: 25 } } },
        'Port 25 is not allowed for SMTP configuration',
      );
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
    it('should throw UnsupportedError (stub, implemented in Chunk 2)', async () => {
      await queryAsAdminWithError(
        { query: SMTP_CONFIGURATION_TEST_MUTATION, variables: { email: 'test@example.com' } },
        'smtpConfigurationTest is not yet implemented',
      );
    });
  });

  describe('Mutation smtpConfigurationDelete', () => {
    it('should delete the configuration by id and return its id', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_DELETE_MUTATION, variables: { id: configId } });
      expect(result.data.smtpConfigurationDelete).toBe(configId);
    });

    it('should return null on query after deletion', async () => {
      const result = await queryAsAdminWithSuccess({ query: SMTP_CONFIGURATION_QUERY });
      expect(result.data.smtpConfiguration).toBeNull();
    });
  });
});
