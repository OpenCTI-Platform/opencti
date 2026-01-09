import type { AuthContext, AuthUser } from '../../types/user';
import { StrategyType } from '../../generated/graphql';
import { logApp } from '../../config/conf';
import LocalStrategy from 'passport-local';
import { login, loginFromProvider } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { findAllSingleSignOn, logAuthInfo } from './singleSignOn-domain';
import { AuthType, EnvStrategyType, isAuthenticationActivatedByIdentifier, type ProviderConfiguration } from '../../config/providers-configuration';
import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { ConfigurationError, UnsupportedError } from '../../config/errors';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { isNotEmptyField } from '../../database/utils';
import * as R from 'ramda';
import { registerAuthenticationProvider, unregisterAuthenticationProvider } from '../../config/providers-initialization';

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
      } else if (currentConfig.type === 'array') {
        ssoConfiguration[currentConfig.key] = JSON.parse(ssoConfiguration[currentConfig.key]);
      } else {
        ssoConfiguration[currentConfig.key] = currentConfig.value;
      }
    }
    return ssoConfiguration;
  } else {
    if (ssoEntity.strategy !== StrategyType.LocalStrategy) {
      throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
    }
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
    return { ...ssoOptions, ...ssoOtherOptions } as PassportSamlConfig;
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
  }
};

export const registerSAMLStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'saml';
  logAuthInfo('Configuring SAML', EnvStrategyType.STRATEGY_SAML, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });

  const providerName = ssoEntity?.label || ssoEntity?.identifier || ssoEntity.id;
  const ssoConfiguration: any = await buildAllConfiguration(ssoEntity);
  const samlOptions: PassportSamlConfig = await buildSAMLOptions(ssoEntity);
  const groupsManagement = ssoEntity.groups_management;
  const orgsManagement = ssoEntity.organizations_management;

  const samlLoginCallback: VerifyWithoutRequest = (profile, done) => {
    if (!profile) {
      throw ConfigurationError('No profile in SAML response, please verify SAML server configuration');
    }

    logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_SAML, { profile, done });
    addUserLoginCount();
    const nameID = profile['nameID'];
    const nameIDFormat = profile['nameIDFormat'];
    const samlAttributes: any = profile['attributes'] ? profile['attributes'] : profile;
    const userEmail = samlAttributes[ssoConfiguration.mail_attribute] || nameID;
    const groupAttributes = groupsManagement?.group_attributes || ['groups'];

    if (ssoConfiguration.mail_attribute && !samlAttributes[ssoConfiguration.mail_attribute]) {
      logAuthInfo(`Custom mail_attribute "${ssoConfiguration.mail_attribute}" in configuration but the custom field is not present SAML server response.`, EnvStrategyType.STRATEGY_SAML);
    }
    const userName = samlAttributes[ssoConfiguration.account_attribute] || '';
    const firstname = samlAttributes[ssoConfiguration.firstname_attribute] || '';
    const lastname = samlAttributes[ssoConfiguration.lastname_attribute] || '';
    const isGroupBaseAccess = (isNotEmptyField(groupsManagement) && isNotEmptyField(groupsManagement?.groups_mapping));
    logAuthInfo('Groups management configuration', EnvStrategyType.STRATEGY_SAML, { groupsManagement: groupsManagement });
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
    logAuthInfo('Login handler', EnvStrategyType.STRATEGY_SAML, { isGroupBaseAccess, groupsToAssociate });
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
    logAuthInfo(`Logout done for ${profile}`, EnvStrategyType.STRATEGY_SAML);
  };
  samlOptions.name = ssoEntity.identifier || 'saml';
  const samlStrategy = new SamlStrategy(samlOptions, samlLoginCallback, samlLogoutCallback);
  // TODO samlStrategy.logout_remote = samlOptions.logout_remote;
  const providerConfig: ProviderConfiguration = { name: providerName, type: AuthType.AUTH_SSO, strategy: EnvStrategyType.STRATEGY_SAML, provider: providerRef };
  registerAuthenticationProvider(providerRef, samlStrategy, providerConfig);
  logAuthInfo('Passport SAML configured', EnvStrategyType.STRATEGY_SAML, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
};

export const registerLocalStrategy = async (providerName: string) => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  const localStrategy = new LocalStrategy({}, (username: string, password: string, done: any) => {
    return login(username, password)
      .then((info) => {
        logAuthInfo('Successfully logged', EnvStrategyType.STRATEGY_SAML, { username });
        addUserLoginCount();
        return done(null, info);
      })
      .catch((err) => {
        done(err);
      });
  });

  // Only one local, remove existing.
  const providerConfig: ProviderConfiguration = { name: providerName, type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LOCAL, provider: 'local' };
  if (isAuthenticationActivatedByIdentifier('local')) {
    unregisterAuthenticationProvider('local');
  }
  registerAuthenticationProvider('local', localStrategy, providerConfig);
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  if (authenticationStrategy.strategy === StrategyType.LocalStrategy) {
    throw UnsupportedError('Disabling local strategy not implemented yet');
  } else {
    unregisterAuthenticationProvider(authenticationStrategy.identifier);
  }
};

export const registerStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  if (authenticationStrategy.strategy && authenticationStrategy.identifier) {
    switch (authenticationStrategy.strategy) {
      case StrategyType.LocalStrategy:
        logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_LOCAL);
        await registerLocalStrategy(authenticationStrategy.name);
        break;
      case StrategyType.SamlStrategy:
        logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_SAML);
        await registerSAMLStrategy(authenticationStrategy);
        break;
      case StrategyType.OpenIdConnectStrategy:
      case StrategyType.LdapStrategy:
      case StrategyType.HeaderStrategy:
      case StrategyType.ClientCertStrategy:
        logApp.warn(`[SSO] ${authenticationStrategy.strategy} not implemented in UI yet`);
        break;

      default:
        logApp.error('[SSO] unknown strategy should not be possible, skipping', {
          name: authenticationStrategy?.name,
          strategy: authenticationStrategy.strategy,
        });
        break;
    }
  } else {
    logApp.error('[SSO INIT] configuration without strategy or identifier should not be possible, skipping', { id: authenticationStrategy?.id, strategy: authenticationStrategy.strategy, identifier: authenticationStrategy.identifier });
  }
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
    logAuthInfo('configuring default local strategy', EnvStrategyType.STRATEGY_LOCAL);
    await registerLocalStrategy('local');
  } else {
    for (let i = 0; i < providersFromDatabase.length; i++) {
      await registerStrategy(providersFromDatabase[i]);
    }
  }
};
