import { StrategyType, type SingleSignOnMigrationResult } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import { now } from 'moment';
import { EnvStrategyType } from '../../config/providers-configuration';
import { nowTime } from '../../utils/format';

const parseLocalStrategyConfiguration = (ssoKey: string, configuration: any) => {
  const providerName = configuration?.label || ssoKey;
  const authEntity: SingleSignOnMigrationResult = {
    strategy: StrategyType.LocalStrategy,
    name: `${providerName}-${nowTime()}`,
    description: `Automatically created from ${ssoKey} at ${now()}`,
    enabled: !(configuration?.disabled === true),
  };
  return authEntity;
};

export const parseSingleSignOnRunConfiguration = async (configuration: any) => {
  const authenticationStrategies: SingleSignOnMigrationResult[] = [];
  for (const ssoKey in configuration) {
    const currentSSOconfig = configuration[ssoKey];

    logApp.info(`[SSO MIGRATION] reading ${ssoKey}`, currentSSOconfig);
    if (currentSSOconfig.strategy) {
      switch (currentSSOconfig.strategy) {
        case EnvStrategyType.STRATEGY_LOCAL:
          authenticationStrategies.push(parseLocalStrategyConfiguration(ssoKey, currentSSOconfig));
          break;

        default:
          logApp.error('[SSO MIGRATION] unknown strategy in configuration', { providerKey: ssoKey, strategy: currentSSOconfig.strategy });
          break;
      }
    } else {
      logApp.error('[SSO MIGRATION] strategy not defined in configuration', { providerKey: ssoKey });
    }
  }
  return authenticationStrategies;
};
