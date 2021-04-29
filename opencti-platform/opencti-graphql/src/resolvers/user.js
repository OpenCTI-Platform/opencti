import * as R from 'ramda';
import { withFilter } from 'graphql-subscriptions';
import {
  addUser,
  authenticateUser,
  batchGroups,
  batchRoleCapabilities,
  batchRoles,
  fetchSessionTtl,
  findAll,
  findById,
  findCapabilities,
  findRoleById,
  findRoles,
  findSessions,
  findUserSessions,
  getCapabilities,
  getMarkings,
  killSession,
  killUserSessions,
  logout,
  meEditField,
  roleAddRelation,
  roleCleanContext,
  roleDelete,
  roleDeleteRelation,
  roleEditContext,
  roleEditField,
  token,
  userAddRelation,
  userCleanContext,
  userDelete,
  userDeleteRelation,
  userEditContext,
  userEditField,
  userRenewToken,
  userWithOrigin,
  bookmarks,
  addBookmark,
  deleteBookmark,
} from '../domain/user';
import { BUS_TOPICS, logApp, logAudit } from '../config/conf';
import passport, { PROVIDERS } from '../config/providers';
import { AuthenticationFailure } from '../config/errors';
import { addRole } from '../domain/grant';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { batchLoader } from '../database/middleware';
import { LOGIN_ACTION } from '../config/audit';

const groupsLoader = batchLoader(batchGroups);
const rolesLoader = batchLoader(batchRoles);
const rolesCapabilitiesLoader = batchLoader(batchRoleCapabilities);

const userResolvers = {
  Query: {
    user: (_, { id }, { user }) => findById(user, id),
    users: (_, args, { user }) => findAll(user, args),
    role: (_, { id }, { user }) => findRoleById(user, id),
    roles: (_, args, { user }) => findRoles(user, args),
    sessions: () => findSessions(),
    capabilities: (_, args, { user }) => findCapabilities(user, args),
    me: (_, args, { user }) => findById(user, user.id),
    bookmarks: (_, { types }, { user }) => bookmarks(user, types),
  },
  User: {
    groups: (current, _, { user }) => groupsLoader.load(current.id, user),
    roles: (current, _, { user }) => rolesLoader.load(current.id, user),
    allowed_marking: (current, _, { user }) => getMarkings(current.id, user.capabilities),
    capabilities: (current) => getCapabilities(current.id),
    token: (current, _, { user }) => token(user, current.id),
    editContext: (current) => fetchEditContext(current.id),
    sessions: (current) => findUserSessions(current.id),
  },
  UserSession: {
    user: (session, _, { user }) => findById(user, session.user_id),
  },
  SessionDetail: {
    ttl: (session) => fetchSessionTtl(session),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role, _, { user }) => rolesCapabilitiesLoader.load(role.id, user),
  },
  Mutation: {
    token: async (_, { input }, { req }) => {
      // We need to iterate on each provider to find one that validated the credentials
      const formProviders = R.filter((p) => p.type === 'FORM', PROVIDERS);
      if (formProviders.length === 0) {
        logApp.error('[AUTH] Cant authenticate without any form providers');
      }
      let loggedUser;
      for (let index = 0; index < formProviders.length; index += 1) {
        const auth = formProviders[index];
        const body = { username: input.email, password: input.password };
        const { userToken, userProvider } = await new Promise((resolve) => {
          passport.authenticate(auth.provider, {}, (err, authInfo, info) => {
            if (err || info) {
              logApp.warn(`[AUTH] ${auth.provider}`, { error: err, info });
              const auditUser = userWithOrigin(req, { user_email: input.email });
              logAudit.error(auditUser, LOGIN_ACTION, { provider: auth.provider });
            }
            resolve({ userToken: authInfo?.token, userProvider: auth.provider });
          })({ body });
        });
        // As soon as credential is validated, stop looking for another provider
        if (userToken) {
          loggedUser = await authenticateUser(req, { providerToken: userToken.uuid, provider: userProvider });
          break;
        }
      }
      if (loggedUser) {
        return loggedUser.token_uuid;
      }
      // User cannot be authenticated in any providers
      throw AuthenticationFailure();
    },
    sessionKill: (_, { id }) => killSession(id),
    userSessionsKill: (_, { id }) => killUserSessions(id),
    logout: (_, args, context) => logout(context.user, context.req, context.res),
    roleEdit: (_, { id }, { user }) => ({
      delete: () => roleDelete(user, id),
      fieldPatch: ({ input }) => roleEditField(user, id, input),
      contextPatch: ({ input }) => roleEditContext(user, id, input),
      contextClean: () => roleCleanContext(user, id),
      relationAdd: ({ input }) => roleAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        roleDeleteRelation(user, id, toId, relationshipType),
    }),
    roleAdd: (_, { input }, { user }) => addRole(user, input),
    userEdit: (_, { id }, { user }) => ({
      delete: () => userDelete(user, id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => userEditContext(user, id, input),
      contextClean: () => userCleanContext(user, id),
      tokenRenew: () => userRenewToken(user, id),
      relationAdd: ({ input }) => userAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        userDeleteRelation(user, id, toId, relationshipType),
    }),
    meEdit: (_, { input }, { user }) => meEditField(user, user.id, input),
    userAdd: (_, { input }, { user }) => addUser(user, input),
    bookmarkAdd: (_, { id, type }, { user }) => addBookmark(user, id, type),
    bookmarkDelete: (_, { id }, { user }) => deleteBookmark(user, id),
  },
  Subscription: {
    user: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        userEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          userCleanContext(user, id);
        });
      },
    },
  },
};

export default userResolvers;
