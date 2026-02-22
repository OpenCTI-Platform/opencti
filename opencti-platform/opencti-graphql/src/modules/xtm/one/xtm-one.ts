import { PLATFORM_VERSION } from '../../../config/conf';
import { logApp } from '../../../config/conf';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreSettings } from '../../../types/settings';
import { getEntityFromCache, getEntitiesListFromCache } from '../../../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../../../schema/internalObject';
import { ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { getEnterpriseEditionActivePem } from '../../settings/licensing';
import { addUserTokenByAdmin } from '../../user/user-domain';
import xtmOneClient from './xtm-one-client';
import type { XtmOneUserEntry } from './xtm-one-client';

const XTM_ONE_TOKEN_NAME = 'XTM One';

/**
 * Register this OpenCTI instance with XTM One.
 *
 * Called on every tick by the XTM One registration manager. The /register
 * endpoint is an upsert so repeated calls are safe and serve as both
 * initial registration and periodic heartbeat.
 *
 * For each user, we check if an "XTM One" named token already exists.
 * If not, we create one and include the plaintext in the registration.
 * Users whose token was already created (and plaintext is no longer
 * available) are still included — XTM One will upsert based on email.
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

  const users: XtmOneUserEntry[] = [];
  try {
    const allUsers = await getEntitiesListFromCache<AuthUser>(context, user, ENTITY_TYPE_USER);
    for (const u of allUsers) {
      if (!u.user_email) continue;
      const apiTokens = (u as any).api_tokens ?? [];
      const existingXtmToken = apiTokens.find((t: any) => t.name === XTM_ONE_TOKEN_NAME);
      if (existingXtmToken) {
        continue;
      }
      try {
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

  const result = await xtmOneClient.register({
    platform_identifier: 'opencti',
    platform_url: settings.platform_url || '',
    platform_title: settings.platform_title || 'OpenCTI Platform',
    platform_version: PLATFORM_VERSION,
    platform_id: settings.internal_id || settings.id,
    enterprise_license_pem: pem,
    users,
  });

  if (result) {
    logApp.info('[XTM One] Registration successful', {
      status: result.status,
      ee_enabled: result.ee_enabled,
      user_integrations: result.user_integrations,
    });
  } else {
    logApp.warn('[XTM One] Registration failed, will retry on next tick');
  }
};
