import { isAuthenticationForcedFromEnv } from './providers-configuration';
import { findAllAuthenticationProvider } from './authenticationProvider-domain';
import { registerStrategy } from './providers';
import type { AuthContext, AuthUser } from '../../types/user';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { initializeEnvAuthenticationProviders } from './providers-initialization';
import { SYSTEM_USER } from '../../utils/access';
import { registerHeaderStrategy } from './provider-header';
import { registerLocalStrategy } from './provider-local';

/**
 * Called during platform initialization.
 * Read Authentication strategy in database and load them.
 * @param context
 * @param user
 */
export const initEnterpriseAuthenticationProviders = async (context: AuthContext, user: AuthUser) => {
  if (!isAuthenticationForcedFromEnv()) {
    const providersFromDatabase = await findAllAuthenticationProvider(context, user);
    for (let i = 0; i < providersFromDatabase.length; i++) {
      await registerStrategy(providersFromDatabase[i]);
    }
  }
};

export const initializeAuthenticationProviders = async (context: AuthContext) => {
  // Local strategy: always register passport strategy at startup
  await registerLocalStrategy();
  const isEE = await isEnterpriseEdition(context);
  if (isEE) {
    // Deprecated providers are env way (Google, Github, Facebook)
    // Also if force env is true, there is still providers with env (OpenId, LDAP, SAML)
    await initializeEnvAuthenticationProviders(context, SYSTEM_USER);
    // If not explicit forced, use database ones
    if (!isAuthenticationForcedFromEnv()) {
      // Header strategy: register handler that reads headers_auth from Settings on each request
      await registerHeaderStrategy(context);
      // No need to do a specific registration for cert
      // Supported providers are in database (openid, ldap, saml, ....)
      await initEnterpriseAuthenticationProviders(context, SYSTEM_USER);
    }
  }
};
