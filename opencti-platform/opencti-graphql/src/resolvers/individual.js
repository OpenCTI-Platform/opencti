import { filter } from 'ramda';
import { addIndividual, findAll, findById, organizations } from '../domain/individual';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { logger } from '../config/conf';
import { stixDomainObjectCleanContext, stixDomainObjectEditContext } from '../domain/stixDomainObject';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import passport, { PROVIDERS } from '../config/providers';
import { AuthenticationFailure } from '../config/errors';
import { addRole } from '../domain/grant';
import { fetchEditContext } from '../database/redis';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const userResolvers = {
  Query: {
    user: (_, { id }) => findById(id, { isUser: true }),
    users: (_, args) => findAll(args, true),
    individual: (_, { id }) => findById(id),
    individuals: (_, args) => findAll(args),
    role: (_, { id }) => findRoleById(id),
    roles: (_, args) => findRoles(args),
    capabilities: (_, args) => findCapabilities(args),
    me: (_, args, { user }) => findById(user.id, { isUser: true }),
  },
  UsersOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.definition`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.value`,
  },
  UsersFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  User: {
    organizations: (user) => organizations(user.id),
    groups: (user) => groups(user.id),
    roles: (user) => getRoles(user.id),
    capabilities: (user) => getCapabilities(user.id),
    token: (user, args, context) => token(user.id, args, context),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role) => getRoleCapabilities(role.id),
  },
  Mutation: {
    token: async (_, { input }, context) => {
      // We need to iterate on each provider to find one that validated the credentials
      const formProviders = filter((p) => p.type === 'FORM', PROVIDERS);
      if (formProviders.length === 0) {
        logger.error('[Configuration] Cant authenticate without any form providers');
      }
      for (let index = 0; index < formProviders.length; index += 1) {
        const auth = formProviders[index];
        // eslint-disable-next-line no-await-in-loop
        const loginToken = await new Promise((resolve) => {
          passport.authenticate(auth.provider, { session: false }, (err, tokenAuth, info) => {
            if (err || info) logger.warn(`[AUTH ERROR] > ${auth.provider}`, { error: err, info });
            resolve(tokenAuth);
          })({ body: { username: input.email, password: input.password } });
        });
        // As soon as credential is validated, set the cookie and return.
        if (loginToken) {
          setAuthenticationCookie(loginToken, context.res);
          return loginToken.uuid;
        }
      }
      // User cannot be authenticated in any providers
      throw AuthenticationFailure();
    },
    logout: (_, args, context) => logout(context.user, context.res),
    roleEdit: (_, { id }, { user }) => ({
      delete: () => roleDelete(user, id),
      fieldPatch: ({ input }) => roleEditField(user, id, input),
      contextPatch: ({ input }) => roleEditContext(user, id, input),
      contextClean: () => roleCleanContext(user, id),
      relationAdd: ({ input }) => roleAddRelation(user, id, input),
      removeCapability: ({ name }) => roleRemoveCapability(user, id, name),
    }),
    roleAdd: (_, { input }, { user }) => addRole(user, input),
    userEdit: (_, { id }, { user }) => ({
      delete: () => userDelete(user, id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      tokenRenew: () => userRenewToken(user, id),
      removeRole: ({ name }) => removeRole(id, name),
      relationAdd: ({ input }) => userAddRelation(user, id, input),
      relationDelete: ({ relationId }) => userDeleteRelation(user, id, relationId),
    }),
    individualEdit: (_, { id }, { user }) => ({
      delete: () => individualDelete(user, id),
      fieldPatch: ({ input }) => individualEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => individualAddRelation(user, id, input),
      relationDelete: ({ relationId }) => individualDeleteRelation(user, id, relationId),
    }),
    meEdit: (_, { input }, { user }) => meEditField(user, user.id, input),
    individualAdd: (_, { input }, { user }) => addIndividual(user, input),
    userAdd: (_, { input }, { user }) => addUser(user, input),
  },
};

export default userResolvers;
