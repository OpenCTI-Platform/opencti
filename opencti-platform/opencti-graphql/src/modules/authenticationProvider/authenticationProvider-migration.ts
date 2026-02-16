/**
 * Migration orchestrator: reads env config, converts via pure functions, persists to database.
 *
 * This module is the ONLY place where side effects (database writes, logging) happen.
 * The actual field-by-field conversion logic is in authenticationProvider-converter.ts.
 */

import type { AuthContext, AuthUser } from '../../types/user';
import { AuthenticationProviderType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { convertAllEnvProviders, type ConvertedProvider } from './authenticationProvider-migration-converter';
import { addAuthenticationProvider, getAllIdentifiers } from './authenticationProvider-domain';
import { isUserHasCapability, SETTINGS_SET_ACCESSES } from '../../utils/access';
import { AuthRequired } from '../../config/errors';
import { isAuthenticationProviderMigrated } from './providers-configuration';

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
  envKey: string;
  status: 'created' | 'skipped_already_migrated' | 'skipped' | 'error';
  type?: string;
  identifier?: string;
  reason?: string;
  warnings?: string[];
}

// ---------------------------------------------------------------------------
// Main migration entry point
// ---------------------------------------------------------------------------

/**
 * Parse environment configuration and persist converted providers to database.
 * Accepts the env configuration object directly to allow testing without nconf.
 */
export const parseAuthenticationProviderConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  envConfiguration: Record<string, any> | undefined,
  dryRun: boolean,
): Promise<MigrationResultEntry[]> => {
  if (!isUserHasCapability(user, SETTINGS_SET_ACCESSES)) {
    throw AuthRequired('SETTINGS_SET_ACCESSES is required');
  }

  const results: MigrationResultEntry[] = [];

  if (!envConfiguration) {
    logApp.info('[MIGRATION] No providers found in environment configuration.');
    return results;
  }

  // 1. Convert all provider entries using pure conversion functions
  const conversionResults = convertAllEnvProviders(envConfiguration);

  // 2. Get existing identifiers to skip already-migrated providers
  const existingIdentifiers = await getAllIdentifiers(context, user);

  // 3. Persist converted providers
  for (const { envKey, result } of conversionResults) {
    if (result.status === 'skipped') {
      results.push({ envKey, status: 'skipped', reason: result.reason });
      logApp.info(`[MIGRATION] Skipped "${envKey}": ${result.reason}`);
      continue;
    }

    if (result.status === 'error') {
      results.push({ envKey, status: 'error', reason: result.reason });
      logApp.error(`[MIGRATION] Error for "${envKey}": ${result.reason}`);
      continue;
    }

    // result.status === 'converted'
    const { provider } = result as { status: 'converted'; provider: ConvertedProvider };
    const identifier = provider.base.identifier_override!; // always set by resolveIdentifier()

    // Skip if already migrated
    if (isAuthenticationProviderMigrated(existingIdentifiers, identifier)) {
      results.push({
        envKey,
        status: 'skipped_already_migrated',
        type: provider.type,
        identifier,
        reason: `Provider "${identifier}" already exists in database.`,
      });
      logApp.info(`[MIGRATION] Skipped "${envKey}" (${provider.type}): already migrated as "${identifier}".`);
      continue;
    }

    // Log warnings from conversion
    for (const warning of provider.warnings) {
      logApp.warn(`[MIGRATION] "${envKey}" (${provider.type}): ${warning}`);
    }

    const providerType = PROVIDER_TYPE_MAP[provider.type];
    if (!providerType) {
      results.push({ envKey, status: 'error', reason: `Unknown provider type "${provider.type}".` });
      continue;
    }

    if (dryRun) {
      results.push({
        envKey,
        status: 'created',
        type: provider.type,
        identifier,
        warnings: provider.warnings,
        reason: '[DRY RUN] Would create provider.',
      });
      logApp.info(`[MIGRATION] [DRY RUN] Would create ${provider.type} provider "${identifier}" from "${envKey}".`);
    } else {
      try {
        const input = { base: provider.base, configuration: provider.configuration };
        await addAuthenticationProvider(context, user, input, providerType, true);
        results.push({
          envKey,
          status: 'created',
          type: provider.type,
          identifier,
          warnings: provider.warnings,
        });
        logApp.info(`[MIGRATION] Created ${provider.type} provider "${identifier}" from "${envKey}".`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        results.push({ envKey, status: 'error', type: provider.type, identifier, reason: message });
        logApp.error(`[MIGRATION] Failed to create ${provider.type} provider "${identifier}": ${message}`);
      }
    }
  }

  return results;
};
