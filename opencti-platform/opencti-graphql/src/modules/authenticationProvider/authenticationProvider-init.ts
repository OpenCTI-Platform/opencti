import { isAuthenticationForcedFromEnv } from './providers-configuration';
import { findAllAuthenticationProvider } from './authenticationProvider-domain';
import { registerStrategy } from './providers';
import type { AuthContext, AuthUser } from '../../types/user';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { initializeEnvAuthenticationProviders } from './providers-initialization';
import { SYSTEM_USER } from '../../utils/access';

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
  const isEE = await isEnterpriseEdition(context);
  if (isEE) {
    // Deprecated providers are env way (Google, Github, Facebook)
    // Also if force env is true, there is still providers with env (OpenId, LDAP, SAML)
    await initializeEnvAuthenticationProviders(context, SYSTEM_USER);

    if (!isAuthenticationForcedFromEnv()) {
      // Supported providers are in database (openid, ldap, saml, ....)
      await initEnterpriseAuthenticationProviders(context, SYSTEM_USER);
    }
  }
};
