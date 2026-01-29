import { EnvStrategyType, isAuthenticationForcedFromEnv, isStrategyActivated } from './providers-configuration';
import { findAllSingleSignOn, logAuthInfo, logAuthWarn } from './singleSignOn-domain';
import { registerLocalStrategy, registerStrategy } from './singleSignOn-providers';
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
    const providersFromDatabase = await findAllSingleSignOn(context, user);

    if (providersFromDatabase.length === 0) {
      // No configuration in database, fallback to default local strategy
      logAuthInfo('configuring default local strategy', EnvStrategyType.STRATEGY_LOCAL);
      await registerLocalStrategy();
    } else {
      for (let i = 0; i < providersFromDatabase.length; i++) {
        await registerStrategy(providersFromDatabase[i]);
      }
    }

    // At the end if there is no local, need to add the internal local
    if (!isStrategyActivated(EnvStrategyType.STRATEGY_LOCAL)) {
      logAuthWarn('No local strategy configured, adding it', EnvStrategyType.STRATEGY_LOCAL);
      await registerLocalStrategy();
    }
  }
};

export const initCommunityAuthenticationProviders = async () => {
  logAuthInfo('configuring default local strategy', EnvStrategyType.STRATEGY_LOCAL);
  await registerLocalStrategy();
};

export const initializeAuthenticationProviders = async (context: AuthContext) => {
  const isEE = await isEnterpriseEdition(context);
  console.log(`---- >>> IsEE:${isEE}`);
  if (isEE) {
    // Deprecated providers are env way (Google, Github, Facebook)
    // Also if force env is true, there is still providers with env (OpenId, LDAP, SAML)
    await initializeEnvAuthenticationProviders(context, SYSTEM_USER);

    if (!isAuthenticationForcedFromEnv()) {
      console.log('---- >>> Not forced to env');
      // Supported providers are in database (local, openid, ldap, saml, ....)
      await initEnterpriseAuthenticationProviders(context, SYSTEM_USER);
    }
  } else {
    console.log('---- >>> COMMU');
    await initCommunityAuthenticationProviders();
  }
};
