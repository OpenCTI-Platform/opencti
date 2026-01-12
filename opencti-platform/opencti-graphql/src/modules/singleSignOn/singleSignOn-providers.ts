import type { AuthContext, AuthUser } from '../../types/user';
import { type GroupsManagement, type OrganizationsManagement, StrategyType } from '../../generated/graphql';
import conf, { logApp } from '../../config/conf';
import LocalStrategy from 'passport-local';
import { login, loginFromProvider } from '../../domain/user';
import { addUserLoginCount } from '../../manager/telemetryManager';
import { findAllSingleSignOn, logAuthError, logAuthInfo, logAuthWarn } from './singleSignOn-domain';
import {
  AuthType,
  EnvStrategyType,
  INTERNAL_SECURITY_PROVIDER,
  isAuthenticationActivatedByIdentifier,
  isStrategyActivated,
  LOCAL_STRATEGY_IDENTIFIER,
  type ProviderConfiguration,
} from '../../config/providers-configuration';
import type { BasicStoreEntitySingleSignOn } from './singleSignOn-types';
import { AuthenticationFailure, ConfigurationError } from '../../config/errors';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml/lib/strategy';
import type { PassportSamlConfig, VerifyWithoutRequest } from '@node-saml/passport-saml/lib/types';
import { isNotEmptyField } from '../../database/utils';
import * as R from 'ramda';
import { registerAuthenticationProvider, unregisterAuthenticationProvider } from '../../config/providers-initialization';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { isSingleSignOnInGuiEnabled } from './singleSignOn';

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

const parseValueAsType = (value: string, type: string) => {
  if (type.toLowerCase() === 'number') {
    return +value;
  } else if (type.toLowerCase() === 'boolean') {
    return value === 'true';
  } else if (type.toLowerCase() === 'array') {
    return JSON.parse(value);
  } else {
    return value;
  }
};

export const convertKeyValueToJsConfiguration = (ssoEntity: BasicStoreEntitySingleSignOn) => {
  if (ssoEntity.configuration) {
    const ssoConfiguration: any = {};
    for (let i = 0; i < ssoEntity.configuration.length; i++) {
      const currentConfig = ssoEntity.configuration[i];
      ssoConfiguration[currentConfig.key] = parseValueAsType(currentConfig.value, currentConfig.type);
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
      ssoOtherOptions[currentConfig.key] = parseValueAsType(currentConfig.value, currentConfig.type);
    }
    return { ...ssoOptions, ...ssoOtherOptions } as PassportSamlConfig;
  } else {
    throw ConfigurationError('SSO configuration is empty', { id: ssoEntity.id, name: ssoEntity.name, strategy: ssoEntity.strategy });
  }
};

export const computeSamlGroupAndOrg = (ssoConfiguration: any, samlProfile: any, groupsManagement?: GroupsManagement, orgsManagement?: OrganizationsManagement) => {
  logAuthInfo('Groups management and organization management configuration', EnvStrategyType.STRATEGY_SAML, { groupsManagement, orgsManagement });

  const samlAttributes: any = samlProfile['attributes'] ? samlProfile['attributes'] : samlProfile;
  const groupAttributes = groupsManagement?.group_attributes || ['groups'];

  const isOrgaMapping = isNotEmptyField(ssoConfiguration.organizations_default) || isNotEmptyField(orgsManagement);
  const computeOrganizationsMapping = () => {
    const orgaDefault = ssoConfiguration.organizations_default ?? [];
    const orgasMapping = orgsManagement?.organizations_mapping || [];
    const orgaPath = orgsManagement?.organizations_path || ['organizations'];
    const samlOrgas = R.path(orgaPath, samlProfile) || [];
    const availableOrgas = Array.isArray(samlOrgas) ? samlOrgas : [samlOrgas];
    const orgasMapper = genConfigMapper(orgasMapping);
    return [...orgaDefault, ...availableOrgas.map((a) => orgasMapper[a]).filter((r) => isNotEmptyField(r))];
  };
  const organizationsToAssociate = isOrgaMapping ? computeOrganizationsMapping() : [];

  const computeGroupsMapping = () => {
    const attrGroups: any[][] = groupAttributes.map((a) => (Array.isArray(samlAttributes[a]) ? samlAttributes[a] : [samlAttributes[a]]));
    const samlGroups = R.flatten(attrGroups).filter((v) => isNotEmptyField(v));
    const groupsMapping = groupsManagement?.groups_mapping || [];
    const groupsMapper = genConfigMapper(groupsMapping);
    return samlGroups.map((a) => groupsMapper[a]).filter((r) => isNotEmptyField(r));
  };
  const groupsToAssociate = R.uniq(computeGroupsMapping());

  return {
    providerGroups: groupsToAssociate,
    providerOrganizations: organizationsToAssociate,
    autoCreateGroup: ssoConfiguration.auto_create_group ?? false,
  };
};

export const computeSamlUserInfo = (ssoConfiguration: any, samlProfile: any) => {
  const samlAttributes: any = samlProfile['attributes'] ? samlProfile['attributes'] : samlProfile;
  const userName = samlAttributes[ssoConfiguration.account_attribute] || '';
  const firstname = samlAttributes[ssoConfiguration.firstname_attribute] || '';
  const lastname = samlAttributes[ssoConfiguration.lastname_attribute] || '';
  const nameID = samlProfile['nameID'];
  const nameIDFormat = samlProfile['nameIDFormat'];
  const userEmail = samlAttributes[ssoConfiguration.mail_attribute] || nameID;
  if (ssoConfiguration.mail_attribute && !samlAttributes[ssoConfiguration.mail_attribute]) {
    logAuthInfo(`Custom mail_attribute "${ssoConfiguration.mail_attribute}" in configuration but the custom field is not present SAML server response.`, EnvStrategyType.STRATEGY_SAML);
  }

  if (!userEmail) {
    throw ConfigurationError('No userEmail found in SAML response, please verify SAML server and OpenCTI configuration', { profile: userEmail, openctiMailAttribute: ssoConfiguration.mail_attribute });
  }
  return { email: userEmail, name: userName, firstname, lastname, provider_metadata: { nameID, nameIDFormat } };
};

export const registerSAMLStrategy = async (ssoEntity: BasicStoreEntitySingleSignOn) => {
  const providerRef = ssoEntity.identifier || 'saml';
  logAuthInfo('Configuring SAML', EnvStrategyType.STRATEGY_SAML, { id: ssoEntity.id, identifier: ssoEntity.identifier, providerRef });
  const providerName = ssoEntity?.label || ssoEntity?.identifier || ssoEntity.id;
  const samlOptions: PassportSamlConfig = await buildSAMLOptions(ssoEntity);

  const samlLoginCallback: VerifyWithoutRequest = (profile, done) => {
    const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity);
    const groupsManagement = ssoEntity.groups_management;
    const orgsManagement = ssoEntity.organizations_management;

    if (!profile) {
      throw ConfigurationError('No profile in SAML response, please verify SAML server configuration');
    }
    logAuthInfo('Successfully logged from provider, computing groups and organizations', EnvStrategyType.STRATEGY_SAML, { profile, done });

    const isGroupBaseAccess = (isNotEmptyField(groupsManagement) && isNotEmptyField(groupsManagement?.groups_mapping));
    const opts = computeSamlGroupAndOrg(ssoConfiguration, profile, groupsManagement, orgsManagement);
    const groupsToAssociate = opts.providerGroups;

    if (!isGroupBaseAccess || groupsToAssociate.length > 0) {
      const opts = computeSamlGroupAndOrg(ssoConfiguration, profile, groupsManagement, orgsManagement);
      const userInfo = computeSamlUserInfo(ssoConfiguration, profile);
      addUserLoginCount();
      logAuthInfo('All configuration is fine, login user with', EnvStrategyType.STRATEGY_SAML, { opts, userInfo });
      providerLoginHandler(userInfo, done, opts);
    } else {
      logAuthInfo('Group configuration not found', EnvStrategyType.STRATEGY_SAML, { isGroupBaseAccess, groupsToAssociate, profile });
      done({ name: 'SAML error', message: 'Restricted access, ask your administrator' });
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

export const registerAdminLocalStrategy = async () => {
  logAuthInfo('Configuring internal local', EnvStrategyType.STRATEGY_LOCAL);
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore as per document new LocalStrategy is the right way, not sure what to do.
  const adminLocalStrategy = new LocalStrategy({}, (username: string, password: string, done: any) => {
    const adminEmail = conf.get('app:admin:email');
    if (username !== adminEmail) {
      return done(AuthenticationFailure());
    }
    return login(username, password)
      .then((info) => {
        addUserLoginCount();
        return done(null, info);
      })
      .catch((err) => {
        done(err);
      });
  });

  // Only one local, remove existing.
  const providerConfig: ProviderConfiguration
    = { name: INTERNAL_SECURITY_PROVIDER, type: AuthType.AUTH_FORM, strategy: EnvStrategyType.STRATEGY_LOCAL, provider: LOCAL_STRATEGY_IDENTIFIER };
  if (isAuthenticationActivatedByIdentifier('local')) {
    unregisterAuthenticationProvider('local');
  }
  registerAuthenticationProvider(INTERNAL_SECURITY_PROVIDER, adminLocalStrategy, providerConfig);
};

export const registerLocalStrategy = async () => {
  logAuthInfo('Configuring local', EnvStrategyType.STRATEGY_LOCAL);
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
  const providerConfig: ProviderConfiguration = {
    name: LOCAL_STRATEGY_IDENTIFIER,
    type: AuthType.AUTH_FORM,
    strategy: EnvStrategyType.STRATEGY_LOCAL,
    provider: LOCAL_STRATEGY_IDENTIFIER,
  };
  if (isAuthenticationActivatedByIdentifier(LOCAL_STRATEGY_IDENTIFIER)) {
    unregisterAuthenticationProvider(LOCAL_STRATEGY_IDENTIFIER);
  }
  registerAuthenticationProvider(LOCAL_STRATEGY_IDENTIFIER, localStrategy, providerConfig);
};

export const refreshStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  await unregisterStrategy(authenticationStrategy);

  if (authenticationStrategy.enabled) {
    await registerStrategy(authenticationStrategy);
  }
};

export const unregisterStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  if (authenticationStrategy.strategy === StrategyType.LocalStrategy) {
    if (authenticationStrategy.identifier === LOCAL_STRATEGY_IDENTIFIER) {
      unregisterAuthenticationProvider(LOCAL_STRATEGY_IDENTIFIER);
      await registerAdminLocalStrategy();
    } else if (authenticationStrategy.identifier === INTERNAL_SECURITY_PROVIDER) {
      unregisterAuthenticationProvider(INTERNAL_SECURITY_PROVIDER);
      await registerLocalStrategy();
    }
  } else {
    unregisterAuthenticationProvider(authenticationStrategy.identifier);
  }
};

export const registerStrategy = async (authenticationStrategy: BasicStoreEntitySingleSignOn) => {
  if (authenticationStrategy.strategy && authenticationStrategy.identifier) {
    switch (authenticationStrategy.strategy) {
      case StrategyType.LocalStrategy:
        logAuthInfo(`Configuring ${authenticationStrategy?.name} - ${authenticationStrategy?.identifier}`, EnvStrategyType.STRATEGY_LOCAL);
        if (authenticationStrategy.enabled) {
          await registerLocalStrategy();
        } else {
          await registerAdminLocalStrategy();
        }
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
        logAuthError('Unknown strategy should not be possible, skipping', {
          name: authenticationStrategy?.name,
          strategy: authenticationStrategy.strategy,
        });
        break;
    }
  } else {
    logAuthError('[SSO INIT] configuration without strategy or identifier should not be possible, skipping', { id: authenticationStrategy?.id, strategy: authenticationStrategy.strategy, identifier: authenticationStrategy.identifier });
  }
};

/**
 * Called during platform initialization.
 * Read Authentication strategy in database and load them.
 * @param context
 * @param user
 */
export const initAuthenticationProviders = async (context: AuthContext, user: AuthUser) => {
  if (!await isEnterpriseEdition(context)) {
    logAuthInfo('configuring default local strategy', EnvStrategyType.STRATEGY_LOCAL);
    await registerLocalStrategy();
  } else {
    if (isSingleSignOnInGuiEnabled) {
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
  }
};
