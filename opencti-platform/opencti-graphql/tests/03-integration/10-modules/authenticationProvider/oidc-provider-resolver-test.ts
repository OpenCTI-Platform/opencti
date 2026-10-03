import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { v4 as uuidv4 } from 'uuid';
import { queryAsAdmin, queryAsAdminWithSuccess } from '../../../utils/testQueryHelper';
import { AuthenticationProviderType, SecretSource } from '../../../../src/generated/graphql';

// NOTE: values below are intentionally generated/fake test data (no real tenant hostnames,
// client identifiers or secrets) so that this test never leaks any customer configuration.
//
// ⚠️ WARNING: This test validates the OIDC provider create/read/delete contract relied upon
// by XTM Hub and the Platform team to automatically instantiate OIDC SSO on trial instances.
// If you need to change this test (input shape, response shape, error messages, or behavior),
// please report/coordinate the change with the XTM Hub and Platform teams beforehand, since
// it may break their trial instance provisioning flow.
const testRunId = uuidv4();
const testIdentifier = `oidc-provider-test-${testRunId}`;
const testCallbackUrl = `https://opencti-test-${testRunId}.invalid/auth/oic/callback`;

const OIDC_PROVIDER_ADD_MUTATION = gql`
  mutation OidcProviderAddTest($input: OidcInput!) {
    oidcProviderAdd(input: $input) {
      id
    }
  }
`;

const OIDC_PROVIDER_DELETE_MUTATION = gql`
  mutation OidcProviderDeleteTest($id: ID!) {
    oidcProviderDelete(id: $id)
  }
`;

const READ_AUTHENTICATION_PROVIDER_QUERY = gql`
  query AuthenticationProviderTest($id: String!) {
    authenticationProvider(id: $id) {
      id
      name
      enabled
      identifier_override
      button_label_override
      type
      configuration {
        ... on OidcConfiguration {
          issuer
          client_id
          client_secret {
            source
          }
          callback_url
          scopes
          audience
          logout_remote
          use_proxy
          user_info_mapping {
            email_expr
            name_expr
            firstname_expr
            lastname_expr
          }
          groups_mapping {
            auto_create_groups
            prevent_default_groups
            groups_expr
            groups_mapping {
              platform
              provider
            }
          }
          organizations_mapping {
            auto_create_organizations
            organizations_expr
          }
          extra_conf {
            key
            value
          }
        }
      }
    }
  }
`;

const buildOidcInput = () => ({
  base: {
    name: `Test OIDC Provider ${testRunId}`,
    description: null,
    enabled: true,
    button_label_override: 'Login with Test IdP',
    identifier_override: testIdentifier,
  },
  configuration: {
    issuer: 'https://idp.example-test.invalid',
    client_id: 'test-client-id',
    client_secret: { new_value_cleartext: 'test-client-secret' },
    callback_url: testCallbackUrl,
    scopes: [],
    audience: null,
    logout_remote: false,
    logout_callback_url: null,
    use_proxy: false,
    extra_conf: [],
    user_info_mapping: {
      email_expr: 'user_info.email',
      name_expr: 'user_info.name',
      firstname_expr: 'user_info.given_name',
      lastname_expr: 'user_info.family_name',
    },
    groups_mapping: {
      auto_create_groups: false,
      default_groups: [],
      groups_expr: ['tokens.id_token.groups'],
      groups_mapping: [
        { platform: 'Administrators', provider: 'Admin' },
        { platform: 'Read Only', provider: 'Reader' },
        { platform: 'Senior Analyst', provider: 'Analyst' },
      ],
      prevent_default_groups: true,
      extend_platform_groups: false,
    },
    organizations_mapping: {
      auto_create_organizations: false,
      default_organizations: [],
      organizations_expr: [],
      organizations_mapping: [],
      organizations_splitter: null,
    },
  },
});

describe('OIDC provider resolver standard behavior', () => {
  // ⚠️ This suite guards the oidcProviderAdd/Delete contract used by XTM Hub & Platform to
  // provision OIDC SSO on trial instances. Report any breaking change to those teams.
  let createdOidcProviderId: string;

  it('should create an OIDC authentication provider', async () => {
    const result = await queryAsAdminWithSuccess({
      query: OIDC_PROVIDER_ADD_MUTATION,
      variables: { input: buildOidcInput() },
    });
    expect(result.data?.oidcProviderAdd.id).toBeDefined();
    createdOidcProviderId = result.data?.oidcProviderAdd.id;
  });

  it('should read back the created OIDC provider with its configuration', async () => {
    const result = await queryAsAdminWithSuccess({
      query: READ_AUTHENTICATION_PROVIDER_QUERY,
      variables: { id: createdOidcProviderId },
    });
    const provider = result.data?.authenticationProvider;
    expect(provider.id).toBe(createdOidcProviderId);
    expect(provider.name).toBe(`Test OIDC Provider ${testRunId}`);
    expect(provider.enabled).toBe(true);
    expect(provider.identifier_override).toBe(testIdentifier);
    expect(provider.type).toBe(AuthenticationProviderType.Oidc);

    const { configuration } = provider;
    expect(configuration.issuer).toBe('https://idp.example-test.invalid');
    expect(configuration.client_id).toBe('test-client-id');
    // The clear text secret must never be stored/returned; only its storage source is exposed.
    expect(configuration.client_secret.source).toBe(SecretSource.Stored);
    expect(configuration.callback_url).toBe(testCallbackUrl);
    expect(configuration.logout_remote).toBe(false);
    expect(configuration.use_proxy).toBe(false);
    expect(configuration.user_info_mapping).toMatchObject({
      email_expr: 'user_info.email',
      name_expr: 'user_info.name',
      firstname_expr: 'user_info.given_name',
      lastname_expr: 'user_info.family_name',
    });
    expect(configuration.groups_mapping.auto_create_groups).toBe(false);
    expect(configuration.groups_mapping.prevent_default_groups).toBe(true);
    expect(configuration.groups_mapping.groups_expr).toEqual(['tokens.id_token.groups']);
    expect(configuration.groups_mapping.groups_mapping).toEqual([
      { platform: 'Administrators', provider: 'Admin' },
      { platform: 'Read Only', provider: 'Reader' },
      { platform: 'Senior Analyst', provider: 'Analyst' },
    ]);
    expect(configuration.organizations_mapping.auto_create_organizations).toBe(false);
  });

  it('should reject creating a second OIDC provider with the same identifier', async () => {
    const result = await queryAsAdmin({
      query: OIDC_PROVIDER_ADD_MUTATION,
      variables: { input: buildOidcInput() },
    });
    expect(result.errors).toBeDefined();
    if (result.errors) {
      expect(result.errors[0].message).toContain('An authentication provider with the same identifier already exists');
    }
  });

  it('should delete the created OIDC provider', async () => {
    const result = await queryAsAdminWithSuccess({
      query: OIDC_PROVIDER_DELETE_MUTATION,
      variables: { id: createdOidcProviderId },
    });
    expect(result.data?.oidcProviderDelete).toBe(createdOidcProviderId);

    const readResult = await queryAsAdmin({
      query: READ_AUTHENTICATION_PROVIDER_QUERY,
      variables: { id: createdOidcProviderId },
    });
    expect(readResult.data?.authenticationProvider).toBeNull();
  });
});
