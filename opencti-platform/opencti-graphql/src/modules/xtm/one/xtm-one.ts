import conf, { PLATFORM_VERSION, logApp } from '../../../config/conf';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import { getEntityFromCache, getEntitiesListFromCache } from '../../../database/cache';
import { internalLoadById } from '../../../database/middleware-loader';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { decodeLicensePem, getEnterpriseEditionActivePem } from '../../settings/licensing';
import { addUserTokenByAdmin } from '../../user/user-domain';
import xtmOneClient from './xtm-one-client';
import type { XtmOneUserEntry } from './xtm-one-client';

const XTM_ONE_TOKEN_NAME = 'XTM One';

let discoveredChatWebToken: string | null = null;

export const getDiscoveredChatWebToken = (): string | null => discoveredChatWebToken;

/**
 * Register this OpenCTI instance with XTM One.
 *
 * Called on every tick by the XTM One registration manager.  The /register
 * endpoint is an upsert so repeated calls are safe and serve as both
 * initial registration and periodic heartbeat.
 *
 * For each user we load from the DB (not cache) to reliably check whether
 * an "XTM One" named token already exists.  Only users who receive a
 * newly-created token are included in the payload — their plaintext key
 * is only available at creation time.
 */
export const registerWithXtmOne = async (context: AuthContext, user: AuthUser): Promise<void> => {
  if (!xtmOneClient.isConfigured()) {
    return;
  }

  const settings = await getEntityFromCache<BasicStoreSettings>(context, user, ENTITY_TYPE_SETTINGS);
  if (!settings) {
    logApp.warn('[XTM One] Cannot register: settings not available');
    return;
  }

  const { pem } = getEnterpriseEditionActivePem(settings);

  let licenseType: string | undefined;
  try {
    const licenseInfo = decodeLicensePem(settings);
    if (licenseInfo.license_validated && licenseInfo.license_type) {
      licenseType = licenseInfo.license_type;
    }
  } catch {
    // license info not available — CE or invalid PEM
  }

  const users: XtmOneUserEntry[] = [];
  try {
    const allUsers = await getEntitiesListFromCache<AuthUser>(context, user, ENTITY_TYPE_USER);
    for (const u of allUsers) {
      if (!u.user_email) continue;
      try {
        // Load from DB (not cache) so the api_tokens check is reliable
        // and we never accidentally create duplicate "XTM One" tokens.
        const freshUser = await internalLoadById<AuthUser>(context, user, u.id);
        if (!freshUser) continue;
        const existingTokens = (freshUser as any).api_tokens ?? [];
        if (existingTokens.some((t: any) => t.name === XTM_ONE_TOKEN_NAME)) {
          continue;
        }
        const newToken = await addUserTokenByAdmin(context, user, u.id, { name: XTM_ONE_TOKEN_NAME });
        users.push({
          email: u.user_email,
          display_name: u.name || u.user_email,
          api_key: newToken.plaintext_token,
        });
      } catch (tokenErr: any) {
        logApp.warn('[XTM One] Failed to create token for user', { email: u.user_email, error: tokenErr.message });
      }
    }
  } catch (err: any) {
    logApp.warn('[XTM One] Failed to collect users', { error: err.message });
  }

  const adminToken = conf.get('app:admin:token') || '';

  const result = await xtmOneClient.register({
    platform_identifier: 'opencti',
    platform_url: settings.platform_url || '',
    platform_title: settings.platform_title || 'OpenCTI Platform',
    platform_version: PLATFORM_VERSION,
    platform_id: settings.internal_id || settings.id,
    enterprise_license_pem: pem,
    license_type: licenseType,
    admin_api_key: adminToken,
    users,
  });

  if (result) {
    if (result.chat_web_token) {
      discoveredChatWebToken = result.chat_web_token;
      logApp.info('[XTM One] Chat web token discovered from registration');
    }
    logApp.info('[XTM One] Registration successful', {
      status: result.status,
      ee_enabled: result.ee_enabled,
      user_integrations: result.user_integrations,
    });
  } else {
    logApp.warn('[XTM One] Registration failed, will retry on next tick');
  }
};
