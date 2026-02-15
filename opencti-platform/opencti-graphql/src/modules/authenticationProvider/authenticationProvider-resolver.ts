import { AuthenticationProviderType, type Resolvers } from '../../generated/graphql';
import {
  addAuthenticationProvider,
  deleteAuthenticationProvider,
  editAuthenticationProvider,
  findAuthenticationProviderById,
  findAuthenticationProviderByIdPaginated,
  getAuthenticationProviderSettings,
  runAuthenticationProviderMigration,
} from './authenticationProvider-domain';

const authenticationProviderResolver: Resolvers = {
  Query: {
    authenticationProvider: (_, { id }, context) => findAuthenticationProviderById(context, context.user, id),
    authenticationProviders: (_, args, context) => findAuthenticationProviderByIdPaginated(context, context.user, args),
    authenticationProviderSettings: (_, __, ___) => getAuthenticationProviderSettings(),
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
