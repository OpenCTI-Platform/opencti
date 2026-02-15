import { isAuthenticationForcedFromEnv } from './providers-configuration';
import { findAllSingleSignOn } from './singleSignOn-domain';
import { registerLocalStrategy, registerSSOStrategy } from './singleSignOn-providers';
import type { AuthContext, AuthUser } from '../../types/user';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { initializeEnvAuthenticationProviders } from './providers-initialization';
import { SYSTEM_USER } from '../../utils/access';
import { registerHeaderStrategy } from './singleSignOn-provider-header';

/**
 * Called during platform initialization.
 * Reads the 3 singleton authentication strategies from Settings entity,
 * then reads non-singleton strategies from the SingleSignOn entities.
 * @param context
 * @param user
 */
export const initEnterpriseAuthenticationProviders = async (context: AuthContext, user: AuthUser) => {
  // SSO Strategies
  const providersFromDatabase = await findAllSingleSignOn(context, user);
  for (let i = 0; i < providersFromDatabase.length; i++) {
    await registerSSOStrategy(providersFromDatabase[i]);
  }
};

export const initializeAuthenticationProviders = async (context: AuthContext) => {
  // Local strategy: always register passport strategy at startup
  await registerLocalStrategy();
  // Register other strategies as EE
  const isEE = await isEnterpriseEdition(context);
  if (isEE) {
    // Deprecated providers are env way (Google, Github, Facebook)
    // Also if force env is true, there is still providers with env (OpenId, LDAP, SAML)
    await initializeEnvAuthenticationProviders(context, SYSTEM_USER);
    // If not explicit forced, use database ones
    if (!isAuthenticationForcedFromEnv()) {
      // Header strategy: register handler that reads headers_auth from Settings on each request
      await registerHeaderStrategy(context);
      // Supported providers are in database (local, openid, ldap, saml, ....)
      await initEnterpriseAuthenticationProviders(context, SYSTEM_USER);
    }
  }
};
