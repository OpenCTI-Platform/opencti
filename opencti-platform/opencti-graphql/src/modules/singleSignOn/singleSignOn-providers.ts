import type { AuthContext, AuthUser } from '../../types/user';
import { StrategyType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import LocalStrategy from 'passport-local';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import passport from 'passport/lib';
import { login, loginFromProvider } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { findAllSingleSignOn } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, PROVIDERS } from '../../config/providers-configuration';
import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { ConfigurationError } from '../../config/errors';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { isNotEmptyField } from '../../database/utils';
import * as R from 'ramda';

export const providerLoginHandler = (userInfo: any, done: any, opts = {}) => {
  loginFromProvider(userInfo, opts)
    .then((user: any) => {
      logApp.info('[SSO] providerLoginHandler user:', user);
      done(null, user);
    })
    .catch((err: any) => {
      logApp.info('[SSO] providerLoginHandler error:', err);
      done(err);
    });
};

export const genConfigMapper = (elements: string[]) => {
  return R.mergeAll(
    elements.map((r) => {
      const data = r.split(':');
      if (data.length !== 2) return {};
      const [remote, octi] = data;
      return { [remote]: octi };
    }),
  );
};

export const buildAllConfiguration = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  if (ssoEntity.configuration) {
    const ssoConfiguration: any = {};
    for (let i = 0; i < ssoEntity.configuration.length; i++) {
      const currentConfig = ssoEntity.configuration[i];
      if (currentConfig.type === 'number') {
        ssoConfiguration[currentConfig.key] = +currentConfig.value;
      } else if (currentConfig.type === 'boolean') {
        ssoConfiguration[currentConfig.key] = currentConfig.value === 'true';
      } else {
        ssoConfiguration[currentConfig.key] = currentConfig.value;
      }
    }
    logApp.info('[SSO SAML] full computed configuration:', { ...ssoConfiguration, idpCert: '***secret***' });
    return ssoConfiguration;
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
  }
};

export const buildSAMLOptions = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  if (ssoEntity.configuration) {
    // 1. Manage passport-saml mandatory fields
    const idpCertConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'idpCert');
    if (!idpCertConfiguration) {
      throw ConfigurationError('idpCert is mandatory for SAML', { id: ssoEntity.id, name: ssoEntity.name });
    }

    const callbackUrlConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'callbackUrl');
    if (!callbackUrlConfiguration) {
      throw ConfigurationError('callbackUrl is mandatory for SAML', { id: ssoEntity.id, name: ssoEntity.name });
    }

    const issuerConfiguration = ssoEntity.configuration.find((configuration) => configuration.key === 'issuer');
    if (!issuerConfiguration) {
      throw ConfigurationError('issuer is mandatory for SAML', { id: ssoEntity.id, name: ssoEntity.name });
    }

    const ssoOptions: PassportSamlConfig = {
      idpCert: idpCertConfiguration.value,
      callbackUrl: callbackUrlConfiguration.value,
      issuer: issuerConfiguration.value,
    };
    // 2. Manage passport-saml optionals fields
    const ssoOtherOptions: any = {};
    for (let i = 0; i < ssoEntity.configuration.length; i++) {
      const currentConfig = ssoEntity.configuration[i];
      if (currentConfig.type === 'number') {
        ssoOtherOptions[currentConfig.key] = +currentConfig.value;
      } else if (currentConfig.type === 'boolean') {
        ssoOtherOptions[currentConfig.key] = currentConfig.value === 'true';
      } else {
        ssoOtherOptions[currentConfig.key] = currentConfig.value;
      }
    }

    const ssoFullOptions = { ...ssoOptions, ...ssoOtherOptions } as PassportSamlConfig;
    logApp.info('[SSO SAML] full computed options:', { ...ssoFullOptions, idpCert: '***secret***' });
    return ssoFullOptions;
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
  }
};

export const addSAMLStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'saml';
  const providerName = ssoEntity?.label || ssoEntity?.identifier || ssoEntity.id;
  const ssoConfiguration: any = await buildAllConfiguration(ssoEntity);
  const samlOptions: PassportSamlConfig = await buildSAMLOptions(ssoEntity);
  const groupsManagement = ssoEntity.groups_management;
  const orgsManagement = ssoEntity.organizations_management;

  const samlLoginCallback: VerifyWithoutRequest = (profile, done) => {
    if (!profile) {
      throw ConfigurationError('No profile in SAML response, please verify SAML server configuration');
    }

    logApp.info('[SSO SAML] Successfully logged', { profile, done });
    addUserLoginCount();
    const nameID = profile['nameID'];
    const nameIDFormat = profile['nameIDFormat'];
    const samlAttributes: any = profile['attributes'] ? profile['attributes'] : profile;
    const userEmail = samlAttributes[ssoConfiguration.mail_attribute] || nameID;
    const groupAttributes = groupsManagement?.group_attributes || ['groups'];

    if (ssoConfiguration.mail_attribute && !samlAttributes[ssoConfiguration.mail_attribute]) {
      logApp.info(`[SSO SAML] custom mail_attribute "${ssoConfiguration.mail_attribute}" in configuration but the custom field is not present SAML server response.`);
    }
    const userName = samlAttributes[ssoConfiguration.account_attribute] || '';
    const firstname = samlAttributes[ssoConfiguration.firstname_attribute] || '';
    const lastname = samlAttributes[ssoConfiguration.lastname_attribute] || '';
    const isGroupBaseAccess = (isNotEmptyField(groupsManagement) && isNotEmptyField(groupsManagement?.groups_mapping));
    logApp.info('[SSO SAML] Groups management configuration', { groupsManagement: groupsManagement });
    // region groups mapping
    const computeGroupsMapping = () => {
      const attrGroups: any[][] = groupAttributes.map((a) => (Array.isArray(samlAttributes[a]) ? samlAttributes[a] : [samlAttributes[a]]));
      const samlGroups = R.flatten(attrGroups).filter((v) => isNotEmptyField(v));
      const groupsMapping = groupsManagement?.groups_mapping || [];
      const groupsMapper = genConfigMapper(groupsMapping);
      return samlGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
    };
    const groupsToAssociate = R.uniq(computeGroupsMapping());
    // endregion
    // region organizations mapping
    const isOrgaMapping = isNotEmptyField(ssoConfiguration.organizations_default) || isNotEmptyField(orgsManagement);
    const computeOrganizationsMapping = () => {
      const orgaDefault = ssoConfiguration.organizations_default ?? [];
      const orgasMapping = orgsManagement?.organizations_mapping || [];
      const orgaPath = orgsManagement?.organizations_path || ['organizations'];
      const samlOrgas = R.path(orgaPath, profile) || [];
      const availableOrgas = Array.isArray(samlOrgas) ? samlOrgas : [samlOrgas];
      const orgasMapper = genConfigMapper(orgasMapping);
      return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
    };
    const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];
    // endregion
    logApp.info('[SSO SAML] Login handler', { isGroupBaseAccess, groupsToAssociate });
    if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
      const opts = {
        providerGroups: groupsToAssociate,
        providerOrganizations: organizationsToAssociate,
        autoCreateGroup: ssoConfiguration.auto_create_group ?? false,
      };
      const userInfo = { email: userEmail, name: userName, firstname, lastname, provider_metadata: { nameID, nameIDFormat } };
      providerLoginHandler(userInfo, done, opts);
    } else {
      // done({ name: 'SAML error', message: 'Restricted access, ask your administrator' });
    }
  };

  const samlLogoutCallback: VerifyWithoutRequest = (profile) => {
    // SAML Logout function
    logApp.info(`[SSO SAML] Logout done for ${profile}`);
  };
  samlOptions.name = ssoEntity.identifier || 'saml';
  const samlStrategy = new SamlStrategy(samlOptions, samlLoginCallback, samlLogoutCallback);

  // TODO samlStrategy.logout_remote = samlOptions.logout_remote;
  logApp.info(`[SSO SAML] passport SAML configured with providerRef:${providerRef}`);
  passport.use(providerRef, samlStrategy);
  PROVIDERS.push({ name: providerName, type: AuthType.AUTH_SSO, strategy: StrategyType.SamlStrategy, provider: providerRef });
};

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
  passport.use(localStrategy);

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
            await addSAMLStrategy(currentSSOconfig);
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
