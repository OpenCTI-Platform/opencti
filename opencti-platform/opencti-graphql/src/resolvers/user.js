import * as R from 'ramda';
import { withFilter } from 'graphql-subscriptions';
import {
  addUser,
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
  userAddRelation,
  userCleanContext,
  userDelete,
  userIdDeleteRelation,
  userEditContext,
  userEditField,
  userWithOrigin,
  bookmarks,
  addBookmark,
  deleteBookmark,
  userRenewToken,
  authenticateUser,
  otpUserGeneration,
  otpUserLogin,
  otpUserActivation, otpUserDeactivation,
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
import { getUserSubscriptions } from '../domain/userSubscription';

const groupsLoader = batchLoader(batchGroups);
const rolesLoader = batchLoader(batchRoles);
const rolesCapabilitiesLoader = batchLoader(batchRoleCapabilities);

const userResolvers = {
  Query: {
    user: (_, { id }, { user }) => findById(user, id),
    otpGeneration: (_, __, { user }) => otpUserGeneration(user),
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
    editContext: (current) => fetchEditContext(current.id),
    sessions: (current) => findUserSessions(current.id),
    userSubscriptions: (current, _, { user }) => getUserSubscriptions(user, current.id),
  },
  MeUser: {
    capabilities: (current) => getCapabilities(current.id),
    userSubscriptions: (current, _, { user }) => getUserSubscriptions(user, current.id),
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
    otpActivation: (_, { input }, { user }) => otpUserActivation(user, input),
    otpDeactivation: (_, __, { user }) => otpUserDeactivation(user, user.id),
    otpLogin: (_, { input }, { req, user }) => otpUserLogin(req, user, input),
    token: async (_, { input }, { req }) => {
      // We need to iterate on each provider to find one that validated the credentials
      const formProviders = R.filter((p) => p.type === 'FORM', PROVIDERS);
      if (formProviders.length === 0) {
        logApp.warn('[AUTH] Cant authenticate without any form providers');
      }
      let loggedUser;
      for (let index = 0; index < formProviders.length; index += 1) {
        const auth = formProviders[index];
        const body = { username: input.email, password: input.password };
        const { user, provider } = await new Promise((resolve) => {
          passport.authenticate(auth.provider, {}, (err, authUser, info) => {
            if (err || info) {
              logApp.warn(`[AUTH] ${auth.provider}`, { error: err, info });
              const auditUser = userWithOrigin(req, { user_email: input.email });
              logAudit.error(auditUser, LOGIN_ACTION, { provider: auth.provider });
            }
            resolve({ user: authUser, provider: auth.provider });
          })({ body });
        });
        // As soon as credential is validated, stop looking for another provider
        if (user) {
          loggedUser = await authenticateUser(req, user, provider);
          break;
        }
      }
      if (loggedUser) {
        return loggedUser.api_token;
      }
      // User cannot be authenticated in any providers
      throw AuthenticationFailure();
    },
    sessionKill: (_, { id }) => killSession(id),
    otpUserDeactivation: (_, { id }, { user }) => otpUserDeactivation(user, id),
    userSessionsKill: (_, { id }) => killUserSessions(id),
    logout: (_, args, context) => logout(context.user, context.req, context.res),
    roleEdit: (_, { id }, { user }) => ({
      delete: () => roleDelete(user, id),
      fieldPatch: ({ input }) => roleEditField(user, id, input),
      contextPatch: ({ input }) => roleEditContext(user, id, input),
      contextClean: () => roleCleanContext(user, id),
      relationAdd: ({ input }) => roleAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => roleDeleteRelation(user, id, toId, relationshipType),
    }),
    roleAdd: (_, { input }, { user }) => addRole(user, input),
    userEdit: (_, { id }, { user }) => ({
      delete: () => userDelete(user, id),
      fieldPatch: ({ input }) => userEditField(user, id, input),
      contextPatch: ({ input }) => userEditContext(user, id, input),
      contextClean: () => userCleanContext(user, id),
      tokenRenew: () => userRenewToken(user, id),
      relationAdd: ({ input }) => userAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => userIdDeleteRelation(user, id, toId, relationshipType),
    }),
    meEdit: (_, { input, password }, { user }) => meEditField(user, user.id, input, password),
    meTokenRenew: (_, __, { user }) => userRenewToken(user, user.id),
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
