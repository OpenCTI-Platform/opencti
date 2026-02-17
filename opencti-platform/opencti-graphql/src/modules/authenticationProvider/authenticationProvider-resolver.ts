import { AuthenticationProviderType, AuthLogLevel, type Resolvers } from '../../generated/graphql';
import { redisGetAuthLogHistory } from '../../database/redis';
import {
  addAuthenticationProvider,
  deleteAuthenticationProvider,
  editAuthenticationProvider,
  findAuthenticationProviderById,
  findAuthenticationProviderByIdPaginated,
  getAuthenticationProviderSettings,
  resolveProviderIdentifier,
  runAuthenticationProviderMigration,
} from './authenticationProvider-domain';
import type { BasicStoreEntityAuthenticationProvider } from './authenticationProvider-types';
import { DatabaseError } from '../../config/errors';

const levelToLevel = (level: string) => {
  switch (level) {
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

const authenticationProviderResolver: Resolvers = {
  AuthenticationProvider: {
    authLogHistory: async (parent) => {
      const identifier = resolveProviderIdentifier(parent as BasicStoreEntityAuthenticationProvider);
      const entries = await redisGetAuthLogHistory(identifier);
      return entries.map(({ timestamp, level, ...others }) => ({
        timestamp: new Date(timestamp),
        level: levelToLevel(level),
        ...others,
      }));
    },
  },
  Query: {
    authenticationProvider: (_, { id }, context) => findAuthenticationProviderById(context, context.user, id),
    authenticationProviders: (_, args, context) => findAuthenticationProviderByIdPaginated(context, context.user, args),
    authenticationProviderSettings: (_, __, ___) => getAuthenticationProviderSettings(),
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
    authenticationProviderRunMigration: (_, { input }, context) => {
      return runAuthenticationProviderMigration(context, context.user, input);
    },
  },
};

export default authenticationProviderResolver;
