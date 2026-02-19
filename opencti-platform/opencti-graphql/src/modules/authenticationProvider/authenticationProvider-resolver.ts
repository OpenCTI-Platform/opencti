import { AuthenticationProviderRuntimeStatus, AuthenticationProviderType, AuthLogLevel, type Resolvers } from '../../generated/graphql';
import { type AuthLogEntry, redisGetAuthLogHistory } from '../../database/redis';
import {
  addAuthenticationProvider,
  deleteAuthenticationProvider,
  editAuthenticationProvider,
  findAuthenticationProviderById,
  findAuthenticationProviderByIdPaginated,
  resolveProviderIdentifier,
} from './authenticationProvider-domain';
import type { BasicStoreEntityAuthenticationProvider } from './authenticationProvider-types';
import { DatabaseError } from '../../config/errors';
import { isProviderRegisteredByInternalId } from './providers-configuration';
import { isProviderStarting } from './providers';

const levelToLevel = (level: string) => {
  switch (level) {
    case 'success':
      return AuthLogLevel.Success;
    case 'info':
      return AuthLogLevel.Info;
    case 'warn':
      return AuthLogLevel.Warn;
    case 'error':
      return AuthLogLevel.Error;
    default:
      throw DatabaseError('Unknown log level', { level });
  }
};

const logsToLogs = (logs: AuthLogEntry[]) => {
  return logs.map(({ timestamp, level, ...others }) => ({
    timestamp: new Date(timestamp),
    level: levelToLevel(level),
    ...others,
  }));
};

const runtimeStatus = (provider: BasicStoreEntityAuthenticationProvider): AuthenticationProviderRuntimeStatus => {
  if (!provider.enabled) {
    return AuthenticationProviderRuntimeStatus.Disabled;
  }
  const isStarting = isProviderStarting(provider.internal_id);
  if (isStarting) {
    return AuthenticationProviderRuntimeStatus.Starting;
  }
  return isProviderRegisteredByInternalId(provider.internal_id)
    ? AuthenticationProviderRuntimeStatus.Active
    : AuthenticationProviderRuntimeStatus.Error;
};

const authenticationProviderResolver: Resolvers = {
  AuthenticationProvider: {
    authLogHistory: async (parent) => {
      const identifier = resolveProviderIdentifier(parent as BasicStoreEntityAuthenticationProvider);
      const entries = await redisGetAuthLogHistory(identifier);
      return logsToLogs(entries);
    },
    runtime_status: (parent) => runtimeStatus(parent as BasicStoreEntityAuthenticationProvider),
  },
  Query: {
    authenticationProvider: (_, { id }, context) => findAuthenticationProviderById(context, context.user, id),
    authenticationProviders: (_, args, context) => findAuthenticationProviderByIdPaginated(context, context.user, args),
    authLogHistoryByIdentifier: async (_, { identifier }) => {
      const entries = await redisGetAuthLogHistory(identifier);
      return logsToLogs(entries);
    },
  },
  AuthenticationConfiguration: {
    __resolveType(obj) {
      if (obj.type === AuthenticationProviderType.Ldap) {
        return 'LdapConfiguration';
      }
      if (obj.type === AuthenticationProviderType.Saml) {
        return 'SamlConfiguration';
      }
      if (obj.type === AuthenticationProviderType.Oidc) {
        return 'OidcConfiguration';
      }
      return obj.type;
    },
  },
  Mutation: {
    oidcProviderAdd: (_, { input }, context) => {
      return addAuthenticationProvider(context, context.user, input, AuthenticationProviderType.Oidc);
    },
    oidcProviderEdit: (_, { id, input }, context) => {
      return editAuthenticationProvider(context, context.user, id, input, AuthenticationProviderType.Oidc);
    },
    oidcProviderDelete: (_, { id }, context) => {
      return deleteAuthenticationProvider(context, context.user, id, AuthenticationProviderType.Oidc);
    },
    samlProviderAdd: (_, { input }, context) => {
      return addAuthenticationProvider(context, context.user, input, AuthenticationProviderType.Saml);
    },
    samlProviderEdit: (_, { id, input }, context) => {
      return editAuthenticationProvider(context, context.user, id, input, AuthenticationProviderType.Saml);
    },
    samlProviderDelete: (_, { id }, context) => {
      return deleteAuthenticationProvider(context, context.user, id, AuthenticationProviderType.Saml);
    },
    ldapProviderAdd: (_, { input }, context) => {
      return addAuthenticationProvider(context, context.user, input, AuthenticationProviderType.Ldap);
    },
    ldapProviderEdit: (_, { id, input }, context) => {
      return editAuthenticationProvider(context, context.user, id, input, AuthenticationProviderType.Ldap);
    },
    ldapProviderDelete: (_, { id }, context) => {
      return deleteAuthenticationProvider(context, context.user, id, AuthenticationProviderType.Ldap);
    },
  },
};

export default authenticationProviderResolver;
