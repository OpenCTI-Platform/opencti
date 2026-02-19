/**
 * Migration orchestrator: reads env config, converts via pure functions, persists to database.
 *
 * This module is the ONLY place where side effects (database writes, logging) happen.
 * The actual field-by-field conversion logic is in authenticationProvider-converter.ts.
 */

import type { AuthContext, AuthUser } from '../../types/user';
import { AuthenticationProviderType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { convertAllSSOEnvProviders } from './authenticationProvider-migration-converter';
import { addAuthenticationProvider, getAllIdentifiers, resolveProviderIdentifier } from './authenticationProvider-domain';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { AuthRequired } from '../../config/errors';
import { isAuthenticationProviderMigrated } from './providers-configuration';
import nconf from 'nconf';
import { getSettings, updateCertAuth, updateHeaderAuth, updateLocalAuth } from '../../domain/settings';

// ---------------------------------------------------------------------------
// Provider type mapping
// ---------------------------------------------------------------------------

const PROVIDER_TYPE_MAP: Record<string, AuthenticationProviderType> = {
  OIDC: AuthenticationProviderType.Oidc,
  SAML: AuthenticationProviderType.Saml,
  LDAP: AuthenticationProviderType.Ldap,
};

// ---------------------------------------------------------------------------
// Migration result for reporting
// ---------------------------------------------------------------------------

export interface MigrationResultEntry {
  env_key: string;
  name: string;
  status: 'created' | 'skipped_already_migrated' | 'skipped' | 'error';
  type?: string;
  identifier?: string;
  reason?: string;
  warnings?: string[];
}

// ---------------------------------------------------------------------------
// Main migration entry point
// ---------------------------------------------------------------------------

const parseMappingStrings = (mapping: any) => {
  if (!mapping || !Array.isArray(mapping)) return [];
  return mapping
    .filter((s) => typeof s === 'string')
    .map((s) => {
      const parts = s.split(':');
      return { provider: parts[0] || '', platform: parts[1] || '' };
    })
    .filter((m) => m.provider || m.platform);
};

/**
 * Ensure local_auth exists.
 * - If absent: create with default { enabled: true }
 * - If present: no-op
 * Returns true if the attribute was absent and had to be created.
 */
const migrateLocalAuthIfNeeded = async (context: AuthContext, user: AuthUser) => {
  const envConfigurations = nconf.get('providers') ?? {};
  const settings = await getSettings(context);
  const local = envConfigurations['local'];
  logApp.info('[SINGLETON-MIGRATION] local_auth is absent, creating with defaults');
  await updateLocalAuth(context, user, settings.id, { enabled: local?.enabled ?? true });
  logApp.info('[SINGLETON-MIGRATION] local_auth successfully ensured');
  return true;
};

/**
 * Ensure headers_auth is in the new nested format.
 * - If absent: create with defaults
 * - If old flat format (no user_info_mapping): convert flat fields to nested
 * - If already nested: no-op
 */
const migrateHeadersAuthIfNeeded = async (context: AuthContext, user: AuthUser) => {
  const envConfigurations = nconf.get('providers') ?? {};
  const certProvider: any | undefined = Object.values(envConfigurations).filter((pr: any) => pr.strategy === 'HeaderStrategy')?.[0];
  const { config, enabled } = certProvider ?? {};
  const settings = await getSettings(context);
  const nested = {
    enabled: enabled ?? false,
    logout_uri: config?.logout_uri ?? null,
    headers_audit: config?.headers_audit ?? [],
    user_info_mapping: {
      email_expr: config?.header_email || 'x-email',
      name_expr: config?.header_name || 'x-name',
      firstname_expr: config?.header_firstname || 'x-firstname',
      lastname_expr: config?.header_lastname || 'x-lastname',
    },
    groups_mapping: {
      default_groups: [],
      groups_expr: config?.groups_management?.groups_header ?? [],
      group_splitter: config?.groups_management?.groups_splitter || null,
      groups_mapping: parseMappingStrings(config?.groups_management?.groups_mapping),
      auto_create_groups: config?.groups_management?.auto_create_group ?? false,
      prevent_default_groups: config?.groups_management?.prevent_default_groups ?? false,
    },
    organizations_mapping: {
      default_organizations: config?.organizations_management?.organizations_default ?? [],
      organizations_expr: config?.organizations_management?.organizations_header ?? [],
      organizations_splitter: config?.organizations_management?.organizations_splitter || null,
      organizations_mapping: parseMappingStrings(config?.organizations_management?.organizations_mapping),
      auto_create_organizations: false,
    },
  };
  await updateHeaderAuth(context, user, settings.id, nested);
  logApp.info('[SINGLETON-MIGRATION] headers_auth successfully ensured in nested format');
};

/**
 * Ensure cert_auth is in the new nested format.
 * - If absent: create with defaults
 * - If old flat format (no user_info_mapping): convert flat fields to nested
 * - If already nested: no-op
 */
const migrateCertAuthIfNeeded = async (context: AuthContext, user: AuthUser) => {
  const envConfigurations = nconf.get('providers') ?? {};
  const certProvider: any | undefined = Object.values(envConfigurations).filter((pr: any) => pr.strategy === 'ClientCertStrategy')?.[0];
  const settings = await getSettings(context);
  const { config, enabled } = certProvider ?? {};
  const nested = {
    enabled: enabled ?? false,
    button_label_override: config?.label ?? 'cert',
    user_info_mapping: {
      email_expr: 'subject.emailAddress',
      name_expr: 'subject.CN',
      firstname_expr: null,
      lastname_expr: null,
    },
    groups_mapping: {
      default_groups: [],
      groups_expr: ['subject.OU'],
      group_splitter: null,
      groups_mapping: [],
      auto_create_groups: false,
      prevent_default_groups: false,
    },
    organizations_mapping: {
      default_organizations: [],
      organizations_expr: ['subject.O'],
      organizations_splitter: null,
      organizations_mapping: [],
      auto_create_organizations: false,
    },
  };

  await updateCertAuth(context, user, settings.id, nested);
  logApp.info('[SINGLETON-MIGRATION] cert_auth successfully ensured in nested format');
};

// Singleton authentications: ensure they all exist and are in the correct nested format

/**
 * Parse environment configuration and persist converted providers to database.
 * Accepts the env configuration object directly to allow testing without nconf.
 */
export const migrateAuthenticationProviders = async (context: AuthContext, user: AuthUser): Promise<void> => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    throw AuthRequired('SETTINGS_SET_ACCESSES is required');
  }
  const envConfigurations = nconf.get('providers') ?? {};
  const conversionResults = convertAllSSOEnvProviders(envConfigurations);
  // 2. Get existing identifiers to skip already-migrated providers
  const existingIdentifiers = await getAllIdentifiers(context, user);
  // 3. Persist converted providers
  logApp.info(`[MIGRATION AUTHENTICATION] Migration of ${existingIdentifiers.length} authenticator.`);
  for (const { envKey, provider } of conversionResults) {
    // Resolve identifier the same way as resolveProviderIdentifier: override, or slugified name
    const identifier = resolveProviderIdentifier(provider.base);

    const providerType = PROVIDER_TYPE_MAP[provider.type];
    if (!providerType) {
      logApp.info(`[MIGRATION AUTHENTICATION] Skipped "${envKey}" (${provider.type}) unknow".`);
      continue;
    }

    // Skip if already migrated
    if (isAuthenticationProviderMigrated(existingIdentifiers, identifier)) {
      logApp.info(`[MIGRATION AUTHENTICATION] Skipped "${envKey}" (${provider.type}): already migrated as "${identifier}".`);
      continue;
    }

    // Log warnings from conversion
    for (const warning of provider.warnings) {
      logApp.warn(`[MIGRATION AUTHENTICATION] "${envKey}" (${provider.type}): ${warning}`);
    }

    try {
      const input = { base: provider.base, configuration: provider.configuration };
      await addAuthenticationProvider(context, user, input, providerType);
      logApp.info(`[MIGRATION AUTHENTICATION] Created ${provider.type} provider "${identifier}" from "${envKey}".`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      logApp.error(`[MIGRATION AUTHENTICATION] Failed to create ${provider.type} provider "${identifier}": ${message}`);
    }
  }
};

export const runAuthenticationProviderMigration = async (context: AuthContext, user: AuthUser) => {
  logApp.info('[AUTH PROVIDER MIGRATION] Migration requested');
  await migrateLocalAuthIfNeeded(context, user);
  await migrateHeadersAuthIfNeeded(context, user);
  await migrateCertAuthIfNeeded(context, user);
  await migrateAuthenticationProviders(context, user);
};
