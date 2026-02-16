import { describe, expect, it } from 'vitest';
import {
  buildBaseInput,
  ConfigExtractor,
  convertAllEnvProviders,
  convertEnvProviderEntry,
  convertLdapEnvConfig,
  convertMappingEntries,
  convertOidcEnvConfig,
  convertSamlEnvConfig,
  resolveIdentifier,
  toExtraConfEntry,
  type EnvProviderEntry,
} from '../../../../src/modules/authenticationProvider/authenticationProvider-migration-converter';
import { ExtraConfEntryType, type OidcConfigurationInput } from '../../../../src/generated/graphql';

// ==========================================================================
// ConfigExtractor
// ==========================================================================

describe('ConfigExtractor', () => {
  it('should track consumed keys and return unconsumed entries', () => {
    const ext = new ConfigExtractor({ a: 1, b: 2, c: 3 });
    ext.get('a');
    ext.get('b');
    const unconsumed = ext.getUnconsumedEntries();
    expect(unconsumed).toStrictEqual([['c', 3]]);
  });

  it('should return default value when key is missing', () => {
    const ext = new ConfigExtractor({});
    expect(ext.get('missing', 'fallback')).toBe('fallback');
  });

  it('should return actual value over default when key exists', () => {
    const ext = new ConfigExtractor({ key: 'real' });
    expect(ext.get('key', 'fallback')).toBe('real');
  });

  it('should mark keys consumed via consume() without reading', () => {
    const ext = new ConfigExtractor({ a: 1, b: 2, deprecated: 'old' });
    ext.get('a');
    ext.consume('deprecated');
    const unconsumed = ext.getUnconsumedEntries();
    expect(unconsumed).toStrictEqual([['b', 2]]);
  });

  it('should consume multiple keys at once', () => {
    const ext = new ConfigExtractor({ a: 1, b: 2, c: 3 });
    ext.consume('a', 'b', 'c');
    expect(ext.getUnconsumedEntries()).toStrictEqual([]);
  });

  it('should report has() without consuming', () => {
    const ext = new ConfigExtractor({ exists: true });
    expect(ext.has('exists')).toBe(true);
    expect(ext.has('missing')).toBe(false);
    // 'exists' should still be unconsumed
    expect(ext.getUnconsumedEntries()).toStrictEqual([['exists', true]]);
  });

  it('should return empty unconsumed when all keys are consumed', () => {
    const ext = new ConfigExtractor({ x: 1, y: 2 });
    ext.get('x');
    ext.get('y');
    expect(ext.getUnconsumedEntries()).toStrictEqual([]);
  });

  it('should return all entries when nothing is consumed', () => {
    const ext = new ConfigExtractor({ a: 1, b: 2 });
    expect(ext.getUnconsumedEntries()).toStrictEqual([['a', 1], ['b', 2]]);
  });
});

// ==========================================================================
// Helper utilities
// ==========================================================================

describe('convertMappingEntries', () => {
  it('should convert valid "remote:platform" entries', () => {
    const result = convertMappingEntries(['admin:Administrators', 'user:Default']);
    expect(result).toStrictEqual([
      { provider: 'admin', platform: 'Administrators' },
      { provider: 'user', platform: 'Default' },
    ]);
  });

  it('should skip entries without exactly one colon', () => {
    const result = convertMappingEntries(['valid:ok', 'invalid', 'too:many:colons']);
    expect(result).toStrictEqual([{ provider: 'valid', platform: 'ok' }]);
  });

  it('should return empty array for undefined input', () => {
    expect(convertMappingEntries(undefined)).toStrictEqual([]);
  });

  it('should return empty array for non-array input', () => {
    expect(convertMappingEntries('not-an-array' as any)).toStrictEqual([]);
  });

  it('should return empty array for empty array', () => {
    expect(convertMappingEntries([])).toStrictEqual([]);
  });
});

describe('toExtraConfEntry', () => {
  it('should convert boolean values', () => {
    expect(toExtraConfEntry('myBool', true)).toStrictEqual({
      type: ExtraConfEntryType.Boolean, key: 'myBool', value: 'true',
    });
    expect(toExtraConfEntry('myBool', false)).toStrictEqual({
      type: ExtraConfEntryType.Boolean, key: 'myBool', value: 'false',
    });
  });

  it('should convert number values', () => {
    expect(toExtraConfEntry('timeout', 5000)).toStrictEqual({
      type: ExtraConfEntryType.Number, key: 'timeout', value: '5000',
    });
    expect(toExtraConfEntry('pi', 3.14)).toStrictEqual({
      type: ExtraConfEntryType.Number, key: 'pi', value: '3.14',
    });
  });

  it('should convert string values', () => {
    expect(toExtraConfEntry('algo', 'sha256')).toStrictEqual({
      type: ExtraConfEntryType.String, key: 'algo', value: 'sha256',
    });
  });

  it('should convert arrays as JSON strings', () => {
    expect(toExtraConfEntry('transforms', ['a', 'b'])).toStrictEqual({
      type: ExtraConfEntryType.String, key: 'transforms', value: '["a","b"]',
    });
  });

  it('should return null for undefined/null values', () => {
    expect(toExtraConfEntry('x', undefined)).toBeNull();
    expect(toExtraConfEntry('x', null)).toBeNull();
  });

  it('should return null for object values', () => {
    expect(toExtraConfEntry('x', { nested: true })).toBeNull();
  });

  it('should return null for function values', () => {
    expect(toExtraConfEntry('x', () => true)).toBeNull();
  });
});

describe('resolveIdentifier', () => {
  it('should use explicit identifier when provided', () => {
    expect(resolveIdentifier({ identifier: 'my-id', strategy: 'OpenIDConnectStrategy' })).toBe('my-id');
  });

  it('should fallback to strategy-specific defaults', () => {
    expect(resolveIdentifier({ strategy: 'OpenIDConnectStrategy' })).toBe('oic');
    expect(resolveIdentifier({ strategy: 'SamlStrategy' })).toBe('saml');
    expect(resolveIdentifier({ strategy: 'LdapStrategy' })).toBe('ldapauth');
    expect(resolveIdentifier({ strategy: 'FacebookStrategy' })).toBe('facebook');
    expect(resolveIdentifier({ strategy: 'GoogleStrategy' })).toBe('google');
    expect(resolveIdentifier({ strategy: 'GithubStrategy' })).toBe('github');
    expect(resolveIdentifier({ strategy: 'Auth0Strategy' })).toBe('auth0');
  });

  it('should fallback to strategy name for unknown strategies', () => {
    expect(resolveIdentifier({ strategy: 'CustomStrategy' })).toBe('CustomStrategy');
  });

  it('should prefer explicit identifier over defaults', () => {
    expect(resolveIdentifier({ identifier: 'custom', strategy: 'SamlStrategy' })).toBe('custom');
  });
});

describe('buildBaseInput', () => {
  it('should use config.label as name when present', () => {
    const entry: EnvProviderEntry = {
      identifier: 'my-provider',
      strategy: 'OpenIDConnectStrategy',
      config: { label: 'My Provider Label', disabled: false },
    };
    const ext = new ConfigExtractor(entry.config!);
    const result = buildBaseInput('oic', entry, ext);
    expect(result.name).toBe('My Provider Label');
    expect(result.enabled).toBe(true);
    expect(result.identifier_override).toBe('my-provider');
    expect(result.button_label_override).toBe('My Provider Label');
    expect(result.description).toContain('oic');
  });

  it('should fallback to envKey as name when no label', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {},
    };
    const ext = new ConfigExtractor(entry.config!);
    const result = buildBaseInput('saml_prod', entry, ext);
    expect(result.name).toBe('saml_prod');
    // No explicit identifier → defaults to strategy default 'saml'
    expect(result.identifier_override).toBe('saml');
  });

  it('should always set identifier_override using strategy default when no identifier', () => {
    const entry: EnvProviderEntry = { strategy: 'LdapStrategy', config: {} };
    const ext = new ConfigExtractor({});
    const result = buildBaseInput('ldap', entry, ext);
    expect(result.identifier_override).toBe('ldapauth');
  });

  it('should set enabled=false when disabled=true', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: { disabled: true },
    };
    const ext = new ConfigExtractor(entry.config!);
    const result = buildBaseInput('ldap', entry, ext);
    expect(result.enabled).toBe(false);
  });

  it('should handle missing config gracefully', () => {
    const entry: EnvProviderEntry = { strategy: 'OpenIDConnectStrategy' };
    const ext = new ConfigExtractor({});
    const result = buildBaseInput('key', entry, ext);
    expect(result.name).toBe('key');
    expect(result.enabled).toBe(true);
    expect(result.identifier_override).toBe('oic');
  });

  it('should consume label and disabled from the extractor', () => {
    const config = { label: 'L', disabled: false, other_key: 'val' };
    const ext = new ConfigExtractor(config);
    buildBaseInput('k', { strategy: 'X', config }, ext);
    const unconsumed = ext.getUnconsumedEntries();
    expect(unconsumed).toStrictEqual([['other_key', 'val']]);
  });
});

// ==========================================================================
// OIDC conversion
// ==========================================================================

describe('convertOidcEnvConfig', () => {
  it('should convert minimal OIDC config', () => {
    const entry: EnvProviderEntry = {
      identifier: 'oic',
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'https://idp.example.com',
        client_id: 'my-client',
        client_secret: 'my-secret',
      },
    };

    const result = convertOidcEnvConfig('oic', entry);

    expect(result.type).toBe('OIDC');
    expect(result.base.name).toBe('oic');
    expect(result.base.identifier_override).toBe('oic'); // explicit identifier

    expect(result.configuration.issuer).toBe('https://idp.example.com');
    expect(result.configuration.client_id).toBe('my-client');
    expect(result.configuration.client_secret_cleartext).toBe('my-secret');
    expect(result.configuration.scopes).toStrictEqual(['openid', 'email', 'profile']);
    expect(result.configuration.logout_remote).toBe(false);
    expect(result.configuration.use_proxy).toBe(false);
    expect(result.warnings).toStrictEqual([]);
  });

  it('should merge scopes from default + groups_scope + organizations_scope', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'https://idp.example.com',
        client_id: 'c',
        client_secret: 's',
        default_scopes: ['openid', 'custom'],
        groups_management: { groups_scope: 'groups' },
        organizations_management: { organizations_scope: 'orgs' },
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.scopes).toStrictEqual(['openid', 'custom', 'groups', 'orgs']);
  });

  it('should deduplicate scopes', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        default_scopes: ['openid', 'groups'],
        groups_management: { groups_scope: 'groups' },
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.scopes).toStrictEqual(['openid', 'groups']);
  });

  it('should convert user info mapping with defaults', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: { issuer: 'x', client_id: 'c', client_secret: 's' },
    };

    const result = convertOidcEnvConfig('oic', entry);
    const mapping = result.configuration.user_info_mapping;
    expect(mapping.email_expr).toBe('user_info.email');
    expect(mapping.name_expr).toBe('user_info.name');
    expect(mapping.firstname_expr).toBe('user_info.given_name');
    expect(mapping.lastname_expr).toBe('user_info.family_name');
  });

  it('should convert user info mapping with custom attributes', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        email_attribute: 'mail',
        name_attribute: 'display_name',
        firstname_attribute: 'first',
        lastname_attribute: 'last',
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    const mapping = result.configuration.user_info_mapping;
    expect(mapping.email_expr).toBe('user_info.mail');
    expect(mapping.name_expr).toBe('user_info.display_name');
    expect(mapping.firstname_expr).toBe('user_info.first');
    expect(mapping.lastname_expr).toBe('user_info.last');
  });

  it('should use id_token prefix when get_user_attributes_from_id_token is set', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        get_user_attributes_from_id_token: true,
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.user_info_mapping.email_expr).toBe('tokens.id_token.email');
    expect(result.warnings).toContain(
      'get_user_attributes_from_id_token=true: user info expressions prefixed with "tokens.id_token" instead of "user_info".',
    );
  });

  it('should convert groups management with full configuration', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        groups_management: {
          groups_path: ['realm_access', 'roles'],
          groups_mapping: ['admin:Administrators', 'user:Connectors'],
          read_userinfo: false,
          token_reference: 'id_token',
        },
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    const gm = result.configuration.groups_mapping;

    // groups_expr built from token_reference + groups_path
    expect(gm.groups_expr).toStrictEqual([
      'tokens.id_token.realm_access',
      'tokens.id_token.roles',
    ]);

    expect(gm.groups_mapping).toStrictEqual([
      { provider: 'admin', platform: 'Administrators' },
      { provider: 'user', platform: 'Connectors' },
    ]);
  });

  it('should convert groups management with read_userinfo=true', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        groups_management: {
          groups_path: ['groups'],
          read_userinfo: true,
        },
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['user_info.groups']);
  });

  it('should convert organizations management', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        organizations_default: ['OpenCTI', 'Filigran'],
        organizations_management: {
          organizations_path: ['orgs'],
          organizations_mapping: ['/Filigran:Filigran'],
          read_userinfo: false,
          token_reference: 'access_token',
        },
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    const om = result.configuration.organizations_mapping;

    expect(om.default_organizations).toStrictEqual(['OpenCTI', 'Filigran']);
    expect(om.organizations_expr).toStrictEqual(['tokens.access_token.orgs']);
    expect(om.organizations_mapping).toStrictEqual([
      { provider: '/Filigran', platform: 'Filigran' },
    ]);
  });

  it('should put unknown keys into extra_conf', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        custom_string: 'hello',
        custom_bool: true,
        custom_number: 42,
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.extra_conf).toStrictEqual([
      { type: ExtraConfEntryType.String, key: 'custom_string', value: 'hello' },
      { type: ExtraConfEntryType.Boolean, key: 'custom_bool', value: 'true' },
      { type: ExtraConfEntryType.Number, key: 'custom_number', value: '42' },
    ]);
  });

  it('should emit warning for roles_management (deprecated)', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        roles_management: { roles_path: ['roles'] },
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.warnings).toContain('roles_management is deprecated and has been ignored.');
  });

  it('should set advanced fields when present', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        audience: 'my-audience',
        logout_remote: true,
        logout_callback_url: 'https://example.com/logout',
        use_proxy: true,
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.audience).toBe('my-audience');
    expect(result.configuration.logout_remote).toBe(true);
    expect(result.configuration.logout_callback_url).toBe('https://example.com/logout');
    expect(result.configuration.use_proxy).toBe(true);
  });

  it('should store callback_url as first-class field when provided in env config', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        callback_url: 'https://example.com/auth/oic/callback',
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.callback_url).toBe('https://example.com/auth/oic/callback');
    // When callback_url is provided, identifier_override should be null
    expect(result.base.identifier_override).toBeNull();
    const extraKeys = result.configuration.extra_conf.map((e) => e.key);
    expect(extraKeys).not.toContain('callback_url');
  });

  it('should have null callback_url when not provided in env config', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.callback_url).toBeNull();
  });
});

// ==========================================================================
// SAML conversion
// ==========================================================================

describe('convertSamlEnvConfig', () => {
  it('should convert minimal SAML config', () => {
    const entry: EnvProviderEntry = {
      identifier: 'saml2',
      strategy: 'SamlStrategy',
      config: {
        issuer: 'openctisaml',
        entry_point: 'https://idp.example.com/saml',
        cert: 'MIID...cert',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);

    expect(result.type).toBe('SAML');
    expect(result.base.name).toBe('saml');
    expect(result.base.identifier_override).toBe('saml2');

    expect(result.configuration.issuer).toBe('openctisaml');
    expect(result.configuration.entry_point).toBe('https://idp.example.com/saml');
    expect(result.configuration.idp_certificate).toBe('MIID...cert');
    expect(result.configuration.private_key_cleartext).toBeNull();
    expect(result.configuration.logout_remote).toBe(false);
    expect(result.configuration.want_assertions_signed).toBe(false);
    expect(result.configuration.want_authn_response_signed).toBe(false);
    expect(result.configuration.force_reauthentication).toBe(false);
    expect(result.warnings).toStrictEqual([]);
  });

  it('should convert SAML config with all first-class boolean fields', () => {
    const entry: EnvProviderEntry = {
      identifier: 'saml2',
      strategy: 'SamlStrategy',
      config: {
        issuer: 'openctisaml',
        entry_point: 'https://idp.example.com/saml',
        cert: 'MIID...cert',
        want_assertions_signed: true,
        want_authn_response_signed: true,
        force_authn: true,
        logout_remote: true,
        signing_cert: 'SP_CERT_PEM',
        sso_binding_type: 'HTTP-POST',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);

    expect(result.configuration.want_assertions_signed).toBe(true);
    expect(result.configuration.want_authn_response_signed).toBe(true);
    expect(result.configuration.force_reauthentication).toBe(true);
    expect(result.configuration.logout_remote).toBe(true);
    expect(result.configuration.signing_cert).toBe('SP_CERT_PEM');
    expect(result.configuration.sso_binding_type).toBe('HTTP-POST');
  });

  it('should convert SAML private_key to private_key_cleartext', () => {
    const entry: EnvProviderEntry = {
      identifier: 'saml2',
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        private_key: '-----BEGIN RSA PRIVATE KEY-----\nXXX\n-----END RSA PRIVATE KEY-----',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.private_key_cleartext).toBe(
      '-----BEGIN RSA PRIVATE KEY-----\nXXX\n-----END RSA PRIVATE KEY-----',
    );
  });

  it('should convert SAML user info mapping with custom attributes', () => {
    const entry: EnvProviderEntry = {
      identifier: 'saml2',
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        mail_attribute: 'TheMail',
        account_attribute: 'MyAccount',
        firstname_attribute: 'theFirstname',
        lastname_attribute: 'theLastName',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    const mapping = result.configuration.user_info_mapping;
    expect(mapping.email_expr).toBe('TheMail');
    expect(mapping.name_expr).toBe('MyAccount');
    expect(mapping.firstname_expr).toBe('theFirstname');
    expect(mapping.lastname_expr).toBe('theLastName');
  });

  it('should convert SAML user info mapping with defaults', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: { issuer: 'x', entry_point: 'y', cert: 'z' },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.user_info_mapping.email_expr).toBe('email');
    expect(result.configuration.user_info_mapping.name_expr).toBe('name');
  });

  it('should convert SAML groups management with group_attributes', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        groups_management: {
          group_attributes: ['samlgroup1', 'samlgroup2'],
          groups_mapping: ['group1:Administrators', 'group2:Connectors'],
        },
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['samlgroup1', 'samlgroup2']);
    expect(result.configuration.groups_mapping.groups_mapping).toStrictEqual([
      { provider: 'group1', platform: 'Administrators' },
      { provider: 'group2', platform: 'Connectors' },
    ]);
  });

  it('should default SAML group_attributes to ["groups"] when groups_management is present but empty', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        groups_management: {},
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['groups']);
    expect(result.configuration.groups_mapping.groups_mapping).toStrictEqual([]);
  });

  it('should convert SAML organizations management', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        organizations_default: ['OpenCTI'],
        organizations_management: {
          organizations_path: ['theOrg'],
          organizations_mapping: ['orgA:OCTIA', 'orgB:OCTIB'],
        },
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    const om = result.configuration.organizations_mapping;
    expect(om.default_organizations).toStrictEqual(['OpenCTI']);
    expect(om.organizations_expr).toStrictEqual(['theOrg']);
    expect(om.organizations_mapping).toStrictEqual([
      { provider: 'orgA', platform: 'OCTIA' },
      { provider: 'orgB', platform: 'OCTIB' },
    ]);
  });

  it('should consume promoted SAML fields as first-class (not in extra_conf)', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        identifier_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        signature_algorithm: 'sha256',
        digest_algorithm: 'sha256',
        authn_context: ['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'],
        disable_requested_authn_context: true,
        disable_request_acs_url: false,
        skip_request_compression: false,
        decryption_pvk: '-----BEGIN PRIVATE KEY-----\nXXX\n-----END PRIVATE KEY-----',
        decryption_cert: '-----BEGIN CERTIFICATE-----\nYYY\n-----END CERTIFICATE-----',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);

    // Verify first-class fields are set correctly
    expect(result.configuration.identifier_format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    expect(result.configuration.signature_algorithm).toBe('sha256');
    expect(result.configuration.digest_algorithm).toBe('sha256');
    expect(result.configuration.authn_context).toStrictEqual(['urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport']);
    expect(result.configuration.disable_requested_authn_context).toBe(true);
    expect(result.configuration.disable_request_acs_url).toBe(false);
    expect(result.configuration.skip_request_compression).toBe(false);
    expect(result.configuration.decryption_pvk_cleartext).toContain('BEGIN PRIVATE KEY');
    expect(result.configuration.decryption_cert).toContain('BEGIN CERTIFICATE');

    // Verify none of these appear in extra_conf
    const extraKeys = result.configuration.extra_conf.map((e) => e.key);
    expect(extraKeys).not.toContain('identifier_format');
    expect(extraKeys).not.toContain('signature_algorithm');
    expect(extraKeys).not.toContain('digest_algorithm');
    expect(extraKeys).not.toContain('authn_context');
    expect(extraKeys).not.toContain('disable_requested_authn_context');
    expect(extraKeys).not.toContain('decryption_pvk');
    expect(extraKeys).not.toContain('decryption_cert');
    expect(extraKeys).toHaveLength(0);
  });

  it('should store callback_url from saml_callback_url or callback_url as first-class field', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        saml_callback_url: 'https://example.com/auth/saml/callback',
        callback_url: 'https://example.com/auth/saml/callback2',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    // saml_callback_url takes priority over callback_url
    expect(result.configuration.callback_url).toBe('https://example.com/auth/saml/callback');
    // When callback_url is provided, identifier_override should be null
    expect(result.base.identifier_override).toBeNull();
    const extraKeys = result.configuration.extra_conf.map((e) => e.key);
    expect(extraKeys).not.toContain('saml_callback_url');
    expect(extraKeys).not.toContain('callback_url');
  });

  it('should fall back to callback_url when saml_callback_url is not set', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        callback_url: 'https://example.com/auth/saml/callback',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.callback_url).toBe('https://example.com/auth/saml/callback');
    // When callback_url is provided, identifier_override should be null
    expect(result.base.identifier_override).toBeNull();
  });

  it('should emit warning for roles_management (deprecated)', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        roles_management: { roles_attributes: ['role1'] },
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.warnings).toContain('roles_management is deprecated and has been ignored.');
  });

  it('should handle disabled SAML config', () => {
    const entry: EnvProviderEntry = {
      identifier: 'saml_disabled',
      strategy: 'SamlStrategy',
      config: {
        disabled: true,
        issuer: 'openctisaml',
        entry_point: 'https://idp.example.com/saml',
        cert: 'MIID...cert',
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.base.enabled).toBe(false);
  });
});

// ==========================================================================
// LDAP conversion
// ==========================================================================

describe('convertLdapEnvConfig', () => {
  it('should convert minimal LDAP config', () => {
    const entry: EnvProviderEntry = {
      identifier: 'ldap',
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://myserver:389',
        bind_dn: 'CN=admin,DC=example,DC=com',
        bind_credentials: 'password123',
        search_base: 'OU=users,DC=example,DC=com',
        search_filter: '(cn={{username}})',
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);

    expect(result.type).toBe('LDAP');
    expect(result.base.name).toBe('ldap');
    expect(result.base.identifier_override).toBe('ldap');

    expect(result.configuration.url).toBe('ldap://myserver:389');
    expect(result.configuration.bind_dn).toBe('CN=admin,DC=example,DC=com');
    expect(result.configuration.bind_credentials_cleartext).toBe('password123');
    expect(result.configuration.search_base).toBe('OU=users,DC=example,DC=com');
    expect(result.configuration.search_filter).toBe('(cn={{username}})');
    expect(result.configuration.allow_self_signed).toBe(false);
    expect(result.warnings).toStrictEqual([]);
  });

  it('should convert bind_credentials to string when it is a number', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389',
        bind_dn: 'x',
        bind_credentials: 12345,
        search_base: 'x',
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.bind_credentials_cleartext).toBe('12345');
  });

  it('should default search_filter when not provided', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389',
        bind_dn: 'x',
        search_base: 'x',
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.search_filter).toBe('(uid={{username}})');
  });

  it('should convert LDAP user info mapping with custom attributes', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        mail_attribute: 'userPrincipalName',
        account_attribute: 'sAMAccountName',
        firstname_attribute: 'givenName',
        lastname_attribute: 'sn',
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    const mapping = result.configuration.user_info_mapping;
    expect(mapping.email_expr).toBe('userPrincipalName');
    expect(mapping.name_expr).toBe('sAMAccountName');
    expect(mapping.firstname_expr).toBe('givenName');
    expect(mapping.lastname_expr).toBe('sn');
  });

  it('should use LDAP-specific defaults for user info (mail, givenName)', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: { url: 'ldap://x:389', bind_dn: 'x', search_base: 'x' },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.user_info_mapping.email_expr).toBe('mail');
    expect(result.configuration.user_info_mapping.name_expr).toBe('givenName');
  });

  it('should convert LDAP groups management with group_attribute', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        group_search_base: 'OU=groups,DC=example,DC=com',
        group_search_filter: '(member={{dn}})',
        groups_management: {
          group_attribute: 'displayName',
          groups_mapping: ['Admins:Administrators'],
        },
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.group_base).toBe('OU=groups,DC=example,DC=com');
    expect(result.configuration.group_filter).toBe('(member={{dn}})');
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['displayName']);
    expect(result.configuration.groups_mapping.groups_mapping).toStrictEqual([
      { provider: 'Admins', platform: 'Administrators' },
    ]);
  });

  it('should default LDAP group_attribute to "cn" when groups_management is present but empty', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        groups_management: {},
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['cn']);
    expect(result.configuration.groups_mapping.groups_mapping).toStrictEqual([]);
  });

  it('should convert LDAP organizations management', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        organizations_default: ['MyOrg'],
        organizations_management: {
          organizations_path: ['department'],
          organizations_mapping: ['IT:Engineering'],
        },
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    const om = result.configuration.organizations_mapping;
    expect(om.default_organizations).toStrictEqual(['MyOrg']);
    expect(om.organizations_expr).toStrictEqual(['department']);
    expect(om.organizations_mapping).toStrictEqual([
      { provider: 'IT', platform: 'Engineering' },
    ]);
  });

  it('should handle allow_self_signed correctly', () => {
    const entry1: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: { url: 'ldap://x:389', bind_dn: 'x', search_base: 'x', allow_self_signed: true },
    };
    expect(convertLdapEnvConfig('ldap', entry1).configuration.allow_self_signed).toBe(true);

    const entry2: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: { url: 'ldap://x:389', bind_dn: 'x', search_base: 'x', allow_self_signed: 'true' },
    };
    expect(convertLdapEnvConfig('ldap', entry2).configuration.allow_self_signed).toBe(true);

    const entry3: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: { url: 'ldap://x:389', bind_dn: 'x', search_base: 'x', allow_self_signed: false },
    };
    expect(convertLdapEnvConfig('ldap', entry3).configuration.allow_self_signed).toBe(false);
  });

  it('should consume promoted LDAP fields as first-class (not in extra_conf)', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        search_attributes: ['mail', 'cn'],
        username_field: 'uid',
        password_field: 'passwd',
        credentials_lookup: 'custom_lookup',
        group_search_attributes: ['cn', 'dn'],
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);

    // Verify first-class fields are set correctly
    expect(result.configuration.search_attributes).toStrictEqual(['mail', 'cn']);
    expect(result.configuration.username_field).toBe('uid');
    expect(result.configuration.password_field).toBe('passwd');
    expect(result.configuration.credentials_lookup).toBe('custom_lookup');
    expect(result.configuration.group_search_attributes).toStrictEqual(['cn', 'dn']);

    // Verify none of these appear in extra_conf
    const extraKeys = result.configuration.extra_conf?.map((e) => e.key) ?? [];
    expect(extraKeys).not.toContain('search_attributes');
    expect(extraKeys).not.toContain('username_field');
    expect(extraKeys).not.toContain('password_field');
    expect(extraKeys).not.toContain('credentials_lookup');
    expect(extraKeys).not.toContain('group_search_attributes');
    expect(extraKeys).toHaveLength(0);
  });

  it('should warn about function-type config keys', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        some_callback: () => 'secret',
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.warnings).toContain(
      'Config key "some_callback" is a function and cannot be migrated.',
    );
  });

  it('should emit warning for roles_management (deprecated)', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x:389', bind_dn: 'x', search_base: 'x',
        roles_management: { roles_path: ['roles'] },
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.warnings).toContain('roles_management is deprecated and has been ignored.');
  });
});

// ==========================================================================
// Top-level dispatcher
// ==========================================================================

describe('convertEnvProviderEntry', () => {
  it('should dispatch OpenIDConnectStrategy to OIDC conversion', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: { issuer: 'x', client_id: 'c', client_secret: 's' },
    };
    const result = convertEnvProviderEntry('oic', entry);
    expect(result.status).toBe('converted');
    if (result.status === 'converted') {
      expect(result.provider.type).toBe('OIDC');
    }
  });

  it('should dispatch SamlStrategy to SAML conversion', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: { issuer: 'x', entry_point: 'y', cert: 'z' },
    };
    const result = convertEnvProviderEntry('saml', entry);
    expect(result.status).toBe('converted');
    if (result.status === 'converted') {
      expect(result.provider.type).toBe('SAML');
    }
  });

  it('should dispatch LdapStrategy to LDAP conversion', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: { url: 'ldap://x', bind_dn: 'x', search_base: 'x' },
    };
    const result = convertEnvProviderEntry('ldap', entry);
    expect(result.status).toBe('converted');
    if (result.status === 'converted') {
      expect(result.provider.type).toBe('LDAP');
    }
  });

  it('should skip disabled entries', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: { disabled: true, issuer: 'x', client_id: 'c', client_secret: 's' },
    };
    const result = convertEnvProviderEntry('oic', entry);
    expect(result.status).toBe('skipped');
    if (result.status === 'skipped') {
      expect(result.reason).toContain('disabled');
    }
  });

  it('should skip singleton strategies (Local, Cert, Header)', () => {
    expect(convertEnvProviderEntry('local', { strategy: 'LocalStrategy' }).status).toBe('skipped');
    expect(convertEnvProviderEntry('cert', { strategy: 'ClientCertStrategy' }).status).toBe('skipped');
    expect(convertEnvProviderEntry('headers', { strategy: 'HeaderStrategy' }).status).toBe('skipped');
  });

  it('should convert deprecated strategies (Facebook, Google, Github, Auth0) to OIDC', () => {
    for (const strategy of ['FacebookStrategy', 'GoogleStrategy', 'GithubStrategy', 'Auth0Strategy']) {
      const result = convertEnvProviderEntry('x', {
        strategy,
        config: { client_id: 'cid', client_secret: 'cs', ...(strategy === 'Auth0Strategy' ? { domain: 'tenant.auth0.com' } : {}) },
      });
      expect(result.status).toBe('converted');
      if (result.status === 'converted') {
        expect(result.provider.type).toBe('OIDC');
        expect(result.provider.warnings.length).toBeGreaterThan(0);
        expect(result.provider.warnings.some((w) => w.includes('deprecated'))).toBe(true);
      }
    }
  });

  it('should error on unknown strategies', () => {
    const result = convertEnvProviderEntry('x', { strategy: 'UnknownStrategy' });
    expect(result.status).toBe('error');
    if (result.status === 'error') {
      expect(result.reason).toContain('Unknown strategy');
    }
  });
});

describe('convertAllEnvProviders', () => {
  it('should convert multiple providers in order', () => {
    const envProviders = {
      oic: {
        identifier: 'oic',
        strategy: 'OpenIDConnectStrategy',
        config: { issuer: 'x', client_id: 'c', client_secret: 's' },
      },
      saml: {
        identifier: 'saml2',
        strategy: 'SamlStrategy',
        config: { issuer: 'x', entry_point: 'y', cert: 'z' },
      },
      ldap: {
        identifier: 'ldap',
        strategy: 'LdapStrategy',
        config: { url: 'ldap://x', bind_dn: 'x', search_base: 'x' },
      },
      local: {
        strategy: 'LocalStrategy',
      },
    };

    const results = convertAllEnvProviders(envProviders);

    expect(results).toHaveLength(4);
    expect(results[0].envKey).toBe('oic');
    expect(results[0].result.status).toBe('converted');

    expect(results[1].envKey).toBe('saml');
    expect(results[1].result.status).toBe('converted');

    expect(results[2].envKey).toBe('ldap');
    expect(results[2].result.status).toBe('converted');

    expect(results[3].envKey).toBe('local');
    expect(results[3].result.status).toBe('skipped');
  });

  it('should handle empty env providers', () => {
    const results = convertAllEnvProviders({});
    expect(results).toStrictEqual([]);
  });

  it('should deduplicate providers with the same resolved identifier', () => {
    const envProviders = {
      first_saml: {
        identifier: 'saml2',
        strategy: 'SamlStrategy',
        config: { issuer: 'first', entry_point: 'y', cert: 'z' },
      },
      second_saml: {
        identifier: 'saml2', // same identifier → duplicate
        strategy: 'SamlStrategy',
        config: { issuer: 'second', entry_point: 'y2', cert: 'z2' },
      },
    };

    const results = convertAllEnvProviders(envProviders);
    expect(results).toHaveLength(2);

    // First one should be converted
    expect(results[0].envKey).toBe('first_saml');
    expect(results[0].result.status).toBe('converted');

    // Second one should be an error (duplicate)
    expect(results[1].envKey).toBe('second_saml');
    expect(results[1].result.status).toBe('error');
    if (results[1].result.status === 'error') {
      expect(results[1].result.reason).toContain('Duplicate identifier');
      expect(results[1].result.reason).toContain('saml2');
      expect(results[1].result.reason).toContain('first_saml');
    }
  });

  it('should deduplicate providers using default identifiers', () => {
    // Two OIDC entries with no explicit identifier → both resolve to default 'oic'
    const envProviders = {
      oic_primary: {
        strategy: 'OpenIDConnectStrategy',
        config: { issuer: 'https://first.example.com', client_id: 'c1', client_secret: 's1' },
      },
      oic_secondary: {
        strategy: 'OpenIDConnectStrategy',
        config: { issuer: 'https://second.example.com', client_id: 'c2', client_secret: 's2' },
      },
    };

    const results = convertAllEnvProviders(envProviders);
    expect(results).toHaveLength(2);

    expect(results[0].result.status).toBe('converted');
    expect(results[1].result.status).toBe('error');
    if (results[1].result.status === 'error') {
      expect(results[1].result.reason).toContain('Duplicate identifier');
      expect(results[1].result.reason).toContain('oic');
    }
  });

  it('should not deduplicate providers with different identifiers', () => {
    const envProviders = {
      oic1: {
        identifier: 'oic-keycloak',
        strategy: 'OpenIDConnectStrategy',
        config: { issuer: 'x', client_id: 'c', client_secret: 's' },
      },
      oic2: {
        identifier: 'oic-azure',
        strategy: 'OpenIDConnectStrategy',
        config: { issuer: 'y', client_id: 'c2', client_secret: 's2' },
      },
    };

    const results = convertAllEnvProviders(envProviders);
    expect(results).toHaveLength(2);
    expect(results[0].result.status).toBe('converted');
    expect(results[1].result.status).toBe('converted');
  });

  it('should not deduplicate skipped entries', () => {
    const envProviders = {
      local1: { strategy: 'LocalStrategy' },
      local2: { strategy: 'LocalStrategy' },
    };

    const results = convertAllEnvProviders(envProviders);
    expect(results).toHaveLength(2);
    // Both skipped, no deduplication error
    expect(results[0].result.status).toBe('skipped');
    expect(results[1].result.status).toBe('skipped');
  });
});

// ==========================================================================
// Complex / real-world scenarios
// ==========================================================================

describe('Real-world configuration scenarios', () => {
  it('should convert a full Keycloak OIDC configuration', () => {
    const entry: EnvProviderEntry = {
      identifier: 'keycloak',
      strategy: 'OpenIDConnectStrategy',
      config: {
        label: 'Login with Keycloak',
        issuer: 'https://keycloak.example.com/realms/master',
        client_id: 'opencti-client',
        client_secret: 'super-secret-key',
        default_scopes: ['openid', 'email', 'profile'],
        logout_remote: true,
        logout_callback_url: 'https://opencti.example.com/logout',
        email_attribute: 'email',
        name_attribute: 'preferred_username',
        groups_management: {
          groups_path: ['realm_access', 'roles'],
          groups_mapping: ['admin:Administrators', 'analyst:Analysts', 'connector:Connectors'],
          groups_scope: 'roles',
          read_userinfo: false,
          token_reference: 'access_token',
        },
        organizations_management: {
          organizations_path: ['organization'],
          organizations_mapping: ['filigran:Filigran', 'partner:Partner'],
          read_userinfo: false,
          token_reference: 'access_token',
        },
        organizations_default: ['Default Org'],
      },
    };

    const result = convertOidcEnvConfig('keycloak', entry);

    expect(result.base.name).toBe('Login with Keycloak');
    expect(result.base.identifier_override).toBe('keycloak');
    expect(result.base.button_label_override).toBe('Login with Keycloak');
    expect(result.base.enabled).toBe(true);

    // Scopes: default + groups_scope (deduped)
    expect(result.configuration.scopes).toStrictEqual(['openid', 'email', 'profile', 'roles']);

    // User info
    expect(result.configuration.user_info_mapping.email_expr).toBe('user_info.email');
    expect(result.configuration.user_info_mapping.name_expr).toBe('user_info.preferred_username');

    // Groups
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual([
      'tokens.access_token.realm_access',
      'tokens.access_token.roles',
    ]);
    expect(result.configuration.groups_mapping.groups_mapping).toHaveLength(3);

    // Orgs
    expect(result.configuration.organizations_mapping.default_organizations).toStrictEqual(['Default Org']);
    expect(result.configuration.organizations_mapping.organizations_expr).toStrictEqual([
      'tokens.access_token.organization',
    ]);
    expect(result.configuration.organizations_mapping.organizations_mapping).toHaveLength(2);

    expect(result.configuration.extra_conf).toStrictEqual([]);
  });

  it('should convert a full Azure AD SAML configuration', () => {
    const entry: EnvProviderEntry = {
      identifier: 'azure-saml',
      strategy: 'SamlStrategy',
      config: {
        label: 'Login with Azure AD',
        issuer: 'https://opencti.example.com',
        entry_point: 'https://login.microsoftonline.com/tenant-id/saml2',
        cert: 'AZURE_IDP_CERT_HERE',
        private_key: 'SP_PRIVATE_KEY',
        signing_cert: 'SP_SIGNING_CERT',
        want_assertions_signed: true,
        want_authn_response_signed: true,
        force_authn: false,
        sso_binding_type: 'HTTP-Redirect',
        identifier_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        signature_algorithm: 'sha256',
        disable_requested_authn_context: true,
        mail_attribute: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        account_attribute: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        groups_management: {
          group_attributes: ['http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'],
          groups_mapping: ['group-id-1:Administrators'],
        },
        organizations_default: ['Azure Org'],
      },
    };

    const result = convertSamlEnvConfig('azure_saml', entry);

    expect(result.base.name).toBe('Login with Azure AD');
    expect(result.configuration.issuer).toBe('https://opencti.example.com');
    expect(result.configuration.entry_point).toBe('https://login.microsoftonline.com/tenant-id/saml2');
    expect(result.configuration.idp_certificate).toBe('AZURE_IDP_CERT_HERE');
    expect(result.configuration.private_key_cleartext).toBe('SP_PRIVATE_KEY');
    expect(result.configuration.signing_cert).toBe('SP_SIGNING_CERT');
    expect(result.configuration.want_assertions_signed).toBe(true);
    expect(result.configuration.want_authn_response_signed).toBe(true);
    expect(result.configuration.force_reauthentication).toBe(false);
    expect(result.configuration.sso_binding_type).toBe('HTTP-Redirect');

    // Promoted fields should be first-class
    expect(result.configuration.identifier_format).toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
    expect(result.configuration.signature_algorithm).toBe('sha256');
    expect(result.configuration.disable_requested_authn_context).toBe(true);

    // extra_conf should be empty
    expect(result.configuration.extra_conf).toHaveLength(0);

    // Groups
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual([
      'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    ]);

    // Orgs
    expect(result.configuration.organizations_mapping.default_organizations).toStrictEqual(['Azure Org']);
  });

  it('should convert a full Active Directory LDAP configuration', () => {
    const entry: EnvProviderEntry = {
      identifier: 'ad-ldap',
      strategy: 'LdapStrategy',
      config: {
        label: 'Login with Active Directory',
        url: 'ldaps://dc.example.com:636',
        bind_dn: 'CN=ServiceAccount,OU=Service,DC=example,DC=com',
        bind_credentials: 'ServiceAccountPassword!',
        search_base: 'OU=Users,DC=example,DC=com',
        search_filter: '(sAMAccountName={{username}})',
        group_search_base: 'OU=Groups,DC=example,DC=com',
        group_search_filter: '(member={{dn}})',
        allow_self_signed: false,
        mail_attribute: 'userPrincipalName',
        account_attribute: 'sAMAccountName',
        firstname_attribute: 'givenName',
        lastname_attribute: 'sn',
        groups_management: {
          group_attribute: 'cn',
          groups_mapping: ['Domain Admins:Administrators', 'Analysts:Analysts'],
        },
        organizations_default: ['Active Directory Org'],
        organizations_management: {
          organizations_path: ['department'],
          organizations_mapping: ['IT:Engineering', 'HR:Human Resources'],
        },
      },
    };

    const result = convertLdapEnvConfig('ad_ldap', entry);

    expect(result.base.name).toBe('Login with Active Directory');
    expect(result.configuration.url).toBe('ldaps://dc.example.com:636');
    expect(result.configuration.bind_dn).toBe('CN=ServiceAccount,OU=Service,DC=example,DC=com');
    expect(result.configuration.bind_credentials_cleartext).toBe('ServiceAccountPassword!');
    expect(result.configuration.search_base).toBe('OU=Users,DC=example,DC=com');
    expect(result.configuration.search_filter).toBe('(sAMAccountName={{username}})');
    expect(result.configuration.group_base).toBe('OU=Groups,DC=example,DC=com');
    expect(result.configuration.group_filter).toBe('(member={{dn}})');
    expect(result.configuration.allow_self_signed).toBe(false);

    // User info
    expect(result.configuration.user_info_mapping.email_expr).toBe('userPrincipalName');
    expect(result.configuration.user_info_mapping.name_expr).toBe('sAMAccountName');
    expect(result.configuration.user_info_mapping.firstname_expr).toBe('givenName');
    expect(result.configuration.user_info_mapping.lastname_expr).toBe('sn');

    // Groups
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['cn']);
    expect(result.configuration.groups_mapping.groups_mapping).toStrictEqual([
      { provider: 'Domain Admins', platform: 'Administrators' },
      { provider: 'Analysts', platform: 'Analysts' },
    ]);

    // Orgs
    expect(result.configuration.organizations_mapping.default_organizations).toStrictEqual(['Active Directory Org']);
    expect(result.configuration.organizations_mapping.organizations_mapping).toStrictEqual([
      { provider: 'IT', platform: 'Engineering' },
      { provider: 'HR', platform: 'Human Resources' },
    ]);

    // No extra conf for clean config
    expect(result.configuration.extra_conf).toStrictEqual([]);
  });

  it('should convert the old test fixture (SAML with all types) to the new format', () => {
    // Reproduces the "all types" test case from singleSignOn-migration-test.ts
    const entry: EnvProviderEntry = {
      identifier: 'saml_all_types',
      strategy: 'SamlStrategy',
      config: {
        label: 'My test SAML with Types',
        issuer: 'openctisaml_all_types',
        entry_point: 'http://localhost:7777/realms/master/protocol/saml',
        saml_callback_url: 'http://localhost:2000/auth/saml/callback',
        cert: 'totallyFakeCert3',
        acceptedClockSkewMs: 5,
        xmlSignatureTransforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
        want_assertions_signed: true,
        organizations_default: ['OpenCTI'],
        decryption_pvk: '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----',
        disable_requested_authn_context: true,
        audience: 'MyAudience',
        account_attribute: 'MyAccount',
        pi: 3.14159,
        auto_create_group: false,
        firstname_attribute: 'theFirstname',
        lastname_attribute: 'theLastName',
        mail_attribute: 'TheMail',
        private_key: 'FAKE_PRIVATE_KEY',
        signature_algorithm: 'sha256',
        want_authn_response_signed: false,
      },
    };

    const result = convertSamlEnvConfig('saml_all_types', entry);

    // First-class fields
    expect(result.configuration.issuer).toBe('openctisaml_all_types');
    expect(result.configuration.entry_point).toBe('http://localhost:7777/realms/master/protocol/saml');
    expect(result.configuration.idp_certificate).toBe('totallyFakeCert3');
    expect(result.configuration.private_key_cleartext).toBe('FAKE_PRIVATE_KEY');
    expect(result.configuration.want_assertions_signed).toBe(true);
    expect(result.configuration.want_authn_response_signed).toBe(false);

    // User info (consumed as first-class)
    expect(result.configuration.user_info_mapping.email_expr).toBe('TheMail');
    expect(result.configuration.user_info_mapping.name_expr).toBe('MyAccount');
    expect(result.configuration.user_info_mapping.firstname_expr).toBe('theFirstname');
    expect(result.configuration.user_info_mapping.lastname_expr).toBe('theLastName');

    // Orgs
    expect(result.configuration.organizations_mapping.default_organizations).toStrictEqual(['OpenCTI']);

    // Promoted fields should be first-class
    expect(result.configuration.decryption_pvk_cleartext).toContain('BEGIN PRIVATE KEY');
    expect(result.configuration.disable_requested_authn_context).toBe(true);
    expect(result.configuration.signature_algorithm).toBe('sha256');

    // Extra conf: only truly unknown keys remain
    const extraKeys = result.configuration.extra_conf.map((e) => e.key);
    expect(extraKeys).toContain('acceptedClockSkewMs'); // number, not consumed
    expect(extraKeys).toContain('xmlSignatureTransforms'); // array, not consumed
    expect(extraKeys).toContain('audience'); // not a consumed SAML key
    expect(extraKeys).toContain('pi'); // number, unknown

    // Promoted fields should NOT be in extra_conf
    expect(extraKeys).not.toContain('decryption_pvk');
    expect(extraKeys).not.toContain('disable_requested_authn_context');
    expect(extraKeys).not.toContain('signature_algorithm');

    // callback_url should NOT be in extra_conf
    expect(extraKeys).not.toContain('saml_callback_url');

    // Verify remaining extra_conf values
    const clockSkew = result.configuration.extra_conf.find((e) => e.key === 'acceptedClockSkewMs');
    expect(clockSkew?.type).toBe(ExtraConfEntryType.Number);
    expect(clockSkew?.value).toBe('5');
  });

  it('should handle an OIDC config with CyberArk credentials_provider (extra_conf)', () => {
    const entry: EnvProviderEntry = {
      identifier: 'oic_cyberark',
      strategy: 'OpenIDConnectStrategy',
      config: {
        label: 'My OpenId with CyberArk',
        issuer: 'http://localhost:9999/realms/master',
        client_id: 'openctioid',
        // No client_secret — CyberArk provides it at runtime
      },
    };

    const result = convertOidcEnvConfig('oic_cyberark', entry);
    expect(result.base.name).toBe('My OpenId with CyberArk');
    expect(result.configuration.issuer).toBe('http://localhost:9999/realms/master');
    expect(result.configuration.client_id).toBe('openctioid');
    // Missing secret gets a 'default' placeholder — migration must not fail on missing fields
    expect(result.configuration.client_secret_cleartext).toBe('default');
  });
});

// ==========================================================================
// Edge cases
// ==========================================================================

// ==========================================================================
// Deprecated strategies → OIDC conversion
// ==========================================================================

describe('convertDeprecatedToOidc', () => {
  it('should convert GoogleStrategy to OIDC with well-known issuer', () => {
    const entry: EnvProviderEntry = {
      identifier: 'google',
      strategy: 'GoogleStrategy',
      config: {
        label: 'Login with Google',
        client_id: 'google-client-id',
        client_secret: 'google-client-secret',
        callback_url: 'https://opencti.example.com/auth/google/callback',
        logout_remote: false,
        domains: ['example.com', 'filigran.io'],
      },
    };

    const result = convertEnvProviderEntry('google', entry);
    expect(result.status).toBe('converted');
    if (result.status !== 'converted') return;

    const { provider } = result;
    expect(provider.type).toBe('OIDC');
    expect(provider.base.name).toBe('Login with Google');
    // callback_url is provided, so identifier_override should be null
    expect(provider.base.identifier_override).toBeNull();

    const config = provider.configuration as OidcConfigurationInput;
    expect(config.issuer).toBe('https://accounts.google.com');
    expect(config.client_id).toBe('google-client-id');
    expect(config.client_secret_cleartext).toBe('google-client-secret');
    expect(config.scopes).toStrictEqual(['openid', 'email', 'profile']);
    expect(config.logout_remote).toBe(false);

    // domains should be preserved in extra_conf for the administrator
    const domainsExtra = config.extra_conf.find((e) => e.key === 'domains');
    expect(domainsExtra).toBeDefined();
    expect(domainsExtra?.value).toBe('["example.com","filigran.io"]');

    // Should have deprecation warning
    expect(provider.warnings.some((w) => w.includes('deprecated'))).toBe(true);
  });

  it('should convert FacebookStrategy to OIDC with placeholder issuer warning', () => {
    const entry: EnvProviderEntry = {
      identifier: 'facebook',
      strategy: 'FacebookStrategy',
      config: {
        client_id: 'fb-client-id',
        client_secret: 'fb-secret',
        callback_url: 'https://opencti.example.com/auth/facebook/callback',
      },
    };

    const result = convertEnvProviderEntry('facebook', entry);
    expect(result.status).toBe('converted');
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.issuer).toBe('https://www.facebook.com');
    expect(config.client_id).toBe('fb-client-id');
    expect(config.scopes).toStrictEqual(['email']);

    // Should warn about placeholder issuer
    expect(result.provider.warnings.some((w) => w.includes('placeholder'))).toBe(true);
    expect(result.provider.warnings.some((w) => w.includes('deprecated'))).toBe(true);
  });

  it('should convert GithubStrategy to OIDC with organizations in extra_conf', () => {
    const entry: EnvProviderEntry = {
      identifier: 'github',
      strategy: 'GithubStrategy',
      config: {
        client_id: 'gh-client-id',
        client_secret: 'gh-secret',
        callback_url: 'https://opencti.example.com/auth/github/callback',
        organizations: ['filigran', 'opencti'],
      },
    };

    const result = convertEnvProviderEntry('github', entry);
    expect(result.status).toBe('converted');
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.issuer).toBe('https://github.com');
    expect(config.client_id).toBe('gh-client-id');
    expect(config.scopes).toStrictEqual(['user:email']);

    // organizations should be preserved in extra_conf
    const orgsExtra = config.extra_conf.find((e) => e.key === 'organizations');
    expect(orgsExtra).toBeDefined();
    expect(orgsExtra?.value).toBe('["filigran","opencti"]');

    // Should warn about placeholder issuer
    expect(result.provider.warnings.some((w) => w.includes('placeholder'))).toBe(true);
  });

  it('should convert Auth0Strategy to OIDC with issuer derived from domain', () => {
    const entry: EnvProviderEntry = {
      identifier: 'auth0',
      strategy: 'Auth0Strategy',
      config: {
        label: 'Login with Auth0',
        domain: 'my-tenant.auth0.com',
        client_id: 'auth0-client-id',
        client_secret: 'auth0-secret',
        callback_url: 'https://opencti.example.com/auth/auth0/callback',
        scope: 'openid email profile groups',
        logout_uri: 'https://opencti.example.com/logout',
        use_proxy: true,
      },
    };

    const result = convertEnvProviderEntry('auth0', entry);
    expect(result.status).toBe('converted');
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.issuer).toBe('https://my-tenant.auth0.com');
    expect(config.client_id).toBe('auth0-client-id');
    expect(config.client_secret_cleartext).toBe('auth0-secret');
    expect(config.scopes).toStrictEqual(['openid', 'email', 'profile', 'groups']);
    expect(config.logout_callback_url).toBe('https://opencti.example.com/logout');
    expect(config.use_proxy).toBe(true);

    // Should have deprecation warning but NOT placeholder warning
    expect(result.provider.warnings.some((w) => w.includes('deprecated'))).toBe(true);
    expect(result.provider.warnings.some((w) => w.includes('placeholder'))).toBe(false);
  });

  it('should warn when Auth0 domain is missing', () => {
    const entry: EnvProviderEntry = {
      identifier: 'auth0',
      strategy: 'Auth0Strategy',
      config: {
        client_id: 'auth0-client-id',
        client_secret: 'auth0-secret',
      },
    };

    const result = convertEnvProviderEntry('auth0', entry);
    expect(result.status).toBe('converted');
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.issuer).toBe('');
    expect(result.provider.warnings.some((w) => w.includes('domain'))).toBe(true);
  });

  it('should convert Auth0 with baseURL as logout_callback_url fallback', () => {
    const entry: EnvProviderEntry = {
      identifier: 'auth0',
      strategy: 'Auth0Strategy',
      config: {
        domain: 'tenant.auth0.com',
        client_id: 'cid',
        client_secret: 'cs',
        baseURL: 'https://opencti.example.com',
      },
    };

    const result = convertEnvProviderEntry('auth0', entry);
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.logout_callback_url).toBe('https://opencti.example.com');
  });

  it('should prefer logout_uri over baseURL for Auth0', () => {
    const entry: EnvProviderEntry = {
      identifier: 'auth0',
      strategy: 'Auth0Strategy',
      config: {
        domain: 'tenant.auth0.com',
        client_id: 'cid',
        client_secret: 'cs',
        logout_uri: 'https://opencti.example.com/logout',
        baseURL: 'https://opencti.example.com',
      },
    };

    const result = convertEnvProviderEntry('auth0', entry);
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.logout_callback_url).toBe('https://opencti.example.com/logout');
  });

  it('should handle Auth0 with legacy camelCase clientID/clientSecret', () => {
    const entry: EnvProviderEntry = {
      identifier: 'auth0',
      strategy: 'Auth0Strategy',
      config: {
        domain: 'tenant.auth0.com',
        client_id: 'cid',
        client_secret: 'cs',
        clientID: 'legacy-cid',
        clientSecret: 'legacy-cs',
      },
    };

    const result = convertEnvProviderEntry('auth0', entry);
    if (result.status !== 'converted') return;

    // clientID/clientSecret should be consumed (not in extra_conf)
    const config = result.provider.configuration as OidcConfigurationInput;
    const extraKeys = config.extra_conf.map((e) => e.key);
    expect(extraKeys).not.toContain('clientID');
    expect(extraKeys).not.toContain('clientSecret');
  });

  it('should store callback_url as first-class field for deprecated strategies', () => {
    const entry: EnvProviderEntry = {
      identifier: 'google',
      strategy: 'GoogleStrategy',
      config: {
        client_id: 'cid',
        client_secret: 'cs',
        callback_url: 'https://opencti.example.com/auth/google/callback',
      },
    };

    const result = convertEnvProviderEntry('google', entry);
    if (result.status !== 'converted') return;

    const config = result.provider.configuration as OidcConfigurationInput;
    expect(config.callback_url).toBe('https://opencti.example.com/auth/google/callback');
    // When callback_url is provided, identifier_override should be null
    expect(result.provider.base.identifier_override).toBeNull();
    const extraKeys = config.extra_conf.map((e) => e.key);
    expect(extraKeys).not.toContain('callback_url');
  });
});

describe('Edge cases', () => {
  it('should handle config with no config property at all', () => {
    const oidcResult = convertOidcEnvConfig('oic', { strategy: 'OpenIDConnectStrategy' });
    expect(oidcResult.configuration.issuer).toBe('');
    expect(oidcResult.configuration.client_id).toBe('');

    const samlResult = convertSamlEnvConfig('saml', { strategy: 'SamlStrategy' });
    expect(samlResult.configuration.issuer).toBe('');

    const ldapResult = convertLdapEnvConfig('ldap', { strategy: 'LdapStrategy' });
    expect(ldapResult.configuration.url).toBe('');
  });

  it('should not put consumed keys into OIDC extra_conf', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        label: 'My Label',
        disabled: false,
        email_attribute: 'mail',
        name_attribute: 'name',
        firstname_attribute: 'given_name',
        lastname_attribute: 'family_name',
        callback_url: 'https://example.com/callback',
        default_scopes: ['openid'],
        audience: 'aud',
        logout_remote: true,
        logout_callback_url: 'https://example.com/logout',
        use_proxy: false,
        get_user_attributes_from_id_token: false,
        groups_management: {},
        organizations_management: {},
        organizations_default: [],
        auto_create_group: true,
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    expect(result.configuration.extra_conf).toStrictEqual([]);
  });

  it('should not put consumed keys into SAML extra_conf', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        label: 'L',
        disabled: false,
        private_key: 'pk',
        saml_callback_url: 'url',
        callback_url: 'url2',
        logout_remote: true,
        want_assertions_signed: true,
        want_authn_response_signed: true,
        signing_cert: 'sc',
        sso_binding_type: 'HTTP-POST',
        force_authn: true,
        identifier_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        signature_algorithm: 'sha256',
        digest_algorithm: 'sha256',
        authn_context: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', // string → wrapped to array by converter
        disable_requested_authn_context: true,
        disable_request_acs_url: false,
        skip_request_compression: false,
        decryption_pvk: 'dpvk',
        decryption_cert: 'dcert',
        mail_attribute: 'mail',
        account_attribute: 'acct',
        firstname_attribute: 'fn',
        lastname_attribute: 'ln',
        groups_management: {},
        organizations_management: {},
        organizations_default: [],
        auto_create_group: true,
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.extra_conf).toStrictEqual([]);
  });

  it('should not put consumed keys into LDAP extra_conf', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x', bind_dn: 'bd', bind_credentials: 'bc',
        search_base: 'sb', search_filter: 'sf',
        group_search_base: 'gsb', group_search_filter: 'gsf',
        allow_self_signed: true,
        search_attributes: ['mail', 'cn'],
        username_field: 'uid',
        password_field: 'passwd',
        credentials_lookup: 'lookup',
        group_search_attributes: ['cn'],
        label: 'L',
        disabled: false,
        mail_attribute: 'mail',
        account_attribute: 'acct',
        firstname_attribute: 'fn',
        lastname_attribute: 'ln',
        groups_management: {},
        organizations_management: {},
        organizations_default: [],
        auto_create_group: true,
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.extra_conf).toStrictEqual([]);
  });

  it('should handle OIDC config with empty groups_management and organizations_management', () => {
    const entry: EnvProviderEntry = {
      strategy: 'OpenIDConnectStrategy',
      config: {
        issuer: 'x', client_id: 'c', client_secret: 's',
        groups_management: {},
        organizations_management: {},
      },
    };

    const result = convertOidcEnvConfig('oic', entry);
    // groups_path defaults to ['groups'], with default token_reference and read_userinfo
    expect(result.configuration.groups_mapping.groups_expr).toStrictEqual(['tokens.access_token.groups']);
    expect(result.configuration.groups_mapping.groups_mapping).toStrictEqual([]);
    expect(result.configuration.organizations_mapping.organizations_expr).toStrictEqual(['tokens.access_token.organizations']);
    expect(result.configuration.organizations_mapping.organizations_mapping).toStrictEqual([]);
  });

  it('should handle SAML config with organizations_management empty', () => {
    const entry: EnvProviderEntry = {
      strategy: 'SamlStrategy',
      config: {
        issuer: 'x', entry_point: 'y', cert: 'z',
        organizations_management: {},
      },
    };

    const result = convertSamlEnvConfig('saml', entry);
    expect(result.configuration.organizations_mapping.organizations_expr).toStrictEqual(['organizations']);
    expect(result.configuration.organizations_mapping.organizations_mapping).toStrictEqual([]);
  });

  it('should handle LDAP config with organizations_management empty', () => {
    const entry: EnvProviderEntry = {
      strategy: 'LdapStrategy',
      config: {
        url: 'ldap://x', bind_dn: 'x', search_base: 'x',
        organizations_management: {},
      },
    };

    const result = convertLdapEnvConfig('ldap', entry);
    expect(result.configuration.organizations_mapping.organizations_expr).toStrictEqual(['organizations']);
    expect(result.configuration.organizations_mapping.organizations_mapping).toStrictEqual([]);
  });
});
