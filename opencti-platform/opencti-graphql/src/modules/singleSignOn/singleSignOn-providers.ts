import type { AuthContext, AuthUser } from '../../types/user';
import { StrategyType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import LocalStrategy from 'passport-local';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import passport from 'passport/lib';
import { login } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { findAllSingleSignOn } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, PROVIDERS } from '../../config/providers-configuration';

export const addLocalStrategy = async (providerName: string) => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  const localStrategy = new LocalStrategy({}, (username: string, password: string, done: any) => {
    return login(username, password)
      .then((info) => {
        logApp.info('[LOCAL] Successfully logged', { username });
        addUserLoginCount();
        return done(null, info);
      })
      .catch((err) => {
        done(err);
      });
  });
  passport.use('local', localStrategy);

  // Only one local can be enabled, remove all others first
  let indexToRemove = PROVIDERS.findIndex((conf) => conf.strategy === StrategyType.LocalStrategy || conf.strategy === EnvStrategyType.STRATEGY_LOCAL);
  while (indexToRemove != -1) {
    PROVIDERS.splice(indexToRemove, 1);
    indexToRemove = PROVIDERS.findIndex((conf) => conf.strategy === StrategyType.LocalStrategy || conf.strategy === EnvStrategyType.STRATEGY_LOCAL);
  }

  PROVIDERS.push({ name: providerName, type: AuthType.AUTH_FORM, strategy: StrategyType.LocalStrategy, provider: 'local' });
};

/**
 * Called during platform initialization.
 * Read Authentication strategy in database and load them.
 * @param context
 * @param user
 */
export const initAuthenticationProviders = async (context: AuthContext, user: AuthUser) => {
  const providersFromDatabase = await findAllSingleSignOn(context, user);

  if (providersFromDatabase.length === 0) {
    // No configuration in database, fallback to default local strategy
    logApp.info('[SSO INIT] configuring default local strategy');
    await addLocalStrategy('local');
  } else {
    for (let i = 0; i < providersFromDatabase.length; i++) {
      const currentSSOconfig = providersFromDatabase[i];
      if (currentSSOconfig.strategy) {
        logApp.info(`[SSO INIT] configuring ${currentSSOconfig.strategy} strategy ${currentSSOconfig?.name}`);
        switch (currentSSOconfig.strategy) {
          case StrategyType.LocalStrategy:
            await addLocalStrategy(currentSSOconfig.name);
            break;
          case StrategyType.SamlStrategy:
            logApp.error(`[SSO INIT] ${currentSSOconfig.strategy} not implemented yet`);
            break;
          case StrategyType.OpenIdConnectStrategy:
            logApp.error(`[SSO INIT] ${currentSSOconfig.strategy} not implemented yet`);
            break;
          case StrategyType.LdapStrategy:
            logApp.error(`[SSO INIT] ${currentSSOconfig.strategy} not implemented yet`);
            break;
          case StrategyType.HeaderStrategy:
            logApp.error(`[SSO INIT] ${currentSSOconfig.strategy} not implemented yet`);
            break;
          case StrategyType.ClientCertStrategy:
            logApp.error(`[SSO INIT] ${currentSSOconfig.strategy} not implemented yet`);
            break;

          default:
            logApp.error('[SSO INIT] unknown strategy should not be possible, skipping', {
              name: currentSSOconfig?.name,
              strategy: currentSSOconfig.strategy,
            });
            break;
        }
      } else {
        logApp.error('[SSO INIT] configuration without strategy should not be possible, skipping', { id: currentSSOconfig?.id });
      }
    }
  }
};
