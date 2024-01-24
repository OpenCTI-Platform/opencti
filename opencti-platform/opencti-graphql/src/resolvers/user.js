import { withFilter } from 'graphql-subscriptions';
import * as R from 'ramda';
import { BUS_TOPICS, ENABLED_DEMO_MODE, logApp } from '../config/conf';
import { AuthenticationFailure } from '../config/errors';
import passport, { PROVIDERS } from '../config/providers';
import { batchLoader } from '../database/middleware';
import { internalLoadById } from '../database/middleware-loader';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import { applicationSession, findSessions, findUserSessions, killSession, killUserSessions } from '../database/session';
import { addRole } from '../domain/grant';
import {
  addBookmark,
  addUser,
  assignOrganizationToUser,
  authenticateUser,
  batchCreator,
  batchGroups,
  batchOrganizations,
  batchRoleCapabilities,
  batchRolesForGroups,
  batchRolesForUsers,
  bookmarks,
  deleteBookmark,
  findAll,
  findAllMembers,
  findAssignees,
  findById,
  findCapabilities,
  findCreators,
  findDefaultDashboards,
  findParticipants,
  findRoleById,
  findRoles,
  getUserEffectiveConfidenceLevel,
  meEditField,
  otpUserActivation,
  otpUserDeactivation,
  otpUserGeneration,
  otpUserLogin,
  roleAddRelation,
  roleCleanContext,
  roleDelete,
  roleDeleteRelation,
  roleEditContext,
  roleEditField,
  userAddRelation,
  userCleanContext,
  userDelete,
  userDeleteOrganizationRelation,
  userEditContext,
  userEditField,
  userIdDeleteRelation,
  userRenewToken,
  userWithOrigin
} from '../domain/user';
import withCancel from '../graphql/subscriptionWrapper';
import { publishUserAction } from '../listener/UserActionListener';
import { findById as findWorskpaceById } from '../modules/workspace/workspace-domain';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { executionContext, REDACTED_USER } from '../utils/access';

const groupsLoader = batchLoader(batchGroups);
const organizationsLoader = batchLoader(batchOrganizations);
const rolesGroupsLoader = batchLoader(batchRolesForGroups);
const rolesUsersLoader = batchLoader(batchRolesForUsers);
const rolesCapabilitiesLoader = batchLoader(batchRoleCapabilities);
const creatorLoader = batchLoader(batchCreator);

const userResolvers = {
  Query: {
    user: (_, { id }, context) => findById(context, context.user, id),
    otpGeneration: (_, __, context) => otpUserGeneration(context.user),
    users: (_, args, context) => findAll(context, context.user, args),
    role: (_, { id }, context) => findRoleById(context, context.user, id),
    roles: (_, args, context) => findRoles(context, context.user, args),
    creators: (_, args, context) => findCreators(context, context.user, args),
    assignees: (_, args, context) => findAssignees(context, context.user, args),
    participants: (_, args, context) => findParticipants(context, context.user, args),
    members: (_, args, context) => findAllMembers(context, context.user, args),
    sessions: () => findSessions(),
    capabilities: (_, args, context) => findCapabilities(context, context.user, args),
    me: (_, __, context) => findById(context, context.user, context.user.id),
    bookmarks: (_, args, context) => bookmarks(context, context.user, args),
  },
  User: {
    roles: (current, args, context) => rolesUsersLoader.load(current.id, context, context.user, args),
    groups: (current, args, context) => groupsLoader.load(current.id, context, context.user, args),
    objectOrganization: (current, args, context) => organizationsLoader.load(current.id, context, context.user, { ...args, withInferences: false }),
    editContext: (current) => fetchEditContext(current.id),
    sessions: (current) => findUserSessions(current.id),
    effective_confidence_level: (current, args, context) => getUserEffectiveConfidenceLevel(current.id, context),
  },
  Member: {
    name: (current, _, context) => {
      if (current.entity_type !== ENTITY_TYPE_USER) {
        return current.name;
      }
      return (ENABLED_DEMO_MODE && context.user.id !== current.id) ? REDACTED_USER.name : current.name;
    },
  },
  MeUser: {
    language: (current) => current.language ?? 'auto',
    unit_system: (current) => current.unit_system ?? 'auto',
    groups: (current, args, context) => groupsLoader.load(current.id, context, context.user, args),
    objectOrganization: (current, _, context) => organizationsLoader.load(current.id, context, context.user, { withInferences: false }),
    default_dashboards: (current, _, context) => findDefaultDashboards(context, context.user, current),
    default_dashboard: (current, _, context) => findWorskpaceById(context, context.user, current.default_dashboard),
  },
  UserSession: {
    user: (session, _, context) => creatorLoader.load(session.user_id, context, context.user),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role, _, context) => rolesCapabilitiesLoader.load(role.id, context, context.user),
  },
  Group: {
    roles: (group, args, context) => rolesGroupsLoader.load(group.id, context, context.user, args),
  },
  EffectiveConfidenceLevelSource: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
  },
  Mutation: {
    otpActivation: (_, { input }, context) => otpUserActivation(context, context.user, input),
    otpDeactivation: (_, __, context) => otpUserDeactivation(context, context.user, context.user.id),
    otpLogin: (_, { input }, { req, user }) => otpUserLogin(req, user, input),
    token: async (_, { input }, { req }) => {
      // We need to iterate on each provider to find one that validated the credentials
      const formProviders = R.filter((p) => p.type === 'FORM', PROVIDERS);
      if (formProviders.length === 0) {
        logApp.warn('Cant authenticate without any form providers');
      }
      let loggedUser;
      for (let index = 0; index < formProviders.length; index += 1) {
        const auth = formProviders[index];
        const body = { username: input.email, password: input.password };
        const { user, provider } = await new Promise((resolve) => {
          passport.authenticate(auth.provider, {}, (err, authUser, info) => {
            if (err || info) {
              logApp.warn(err, { info, provider: auth.provider });
            }
            resolve({ user: authUser, provider: auth.provider });
          })({ body });
        });
        // As soon as credential is validated, stop looking for another provider
        if (user) {
          const context = executionContext(`${provider}_strategy`);
          loggedUser = await authenticateUser(context, req, user, provider);
          break;
        }
      }
      if (loggedUser) {
        return loggedUser.api_token;
      }
      const auditUser = userWithOrigin(req, { user_email: input.email });
      await publishUserAction({
        user: auditUser,
        event_type: 'authentication',
        event_scope: 'login',
        event_access: 'administration',
        status: 'error',
        context_data: { username: ENABLED_DEMO_MODE ? REDACTED_USER.name : input.email, provider: 'form' }
      });
      // User cannot be authenticated in any providers
      throw AuthenticationFailure();
    },
    sessionKill: async (_, { id }, context) => {
      const { store } = applicationSession;
      const userSessionId = id.split(store.prefix)[1]; // Prefix must be removed on this case
      const kill = await killSession(userSessionId);
      const { user } = kill.session;
      const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.name : user.user_email;
      await publishUserAction({
        user: context.user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `kills \`specific session\` for user \`${actionEmail}\``,
        context_data: { id: user.id, entity_type: ENTITY_TYPE_USER, input: { user_id: user.id, session_id: kill.sessionId } }
      });
      return id;
    },
    otpUserDeactivation: (_, { id }, context) => otpUserDeactivation(context, context.user, id),
    userSessionsKill: async (_, { id }, context) => {
      const user = await internalLoadById(context, context.user, id);
      const sessions = await killUserSessions(id);
      const sessionIds = sessions.map((s) => s.sessionId);
      const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.name : user.user_email;
      await publishUserAction({
        user: context.user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `kills \`all sessions\` for user \`${actionEmail}\``,
        context_data: { id: user.id, entity_type: ENTITY_TYPE_USER, input: { user_id: id } }
      });
      return sessionIds;
    },
    roleEdit: (_, { id }, context) => ({
      delete: () => roleDelete(context, context.user, id),
      fieldPatch: ({ input }) => roleEditField(context, context.user, id, input),
      contextPatch: ({ input }) => roleEditContext(context, context.user, id, input),
      contextClean: () => roleCleanContext(context, context.user, id),
      relationAdd: ({ input }) => roleAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => {
        return roleDeleteRelation(context, context.user, id, toId, relationshipType);
      },
    }),
    roleAdd: (_, { input }, context) => addRole(context, context.user, input),
    userEdit: (_, { id }, context) => ({
      delete: () => userDelete(context, context.user, id),
      fieldPatch: ({ input }) => userEditField(context, context.user, id, input),
      contextPatch: ({ input }) => userEditContext(context, context.user, id, input),
      contextClean: () => userCleanContext(context, context.user, id),
      tokenRenew: () => userRenewToken(context, context.user, id),
      relationAdd: ({ input }) => userAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => {
        return userIdDeleteRelation(context, context.user, id, toId, relationshipType);
      },
      organizationAdd: ({ organizationId }) => assignOrganizationToUser(context, context.user, id, organizationId),
      organizationDelete: ({ organizationId }) => userDeleteOrganizationRelation(context, context.user, id, organizationId),
    }),
    meEdit: (_, { input, password }, context) => meEditField(context, context.user, context.user.id, input, password),
    meTokenRenew: (_, __, context) => userRenewToken(context, context.user, context.user.id),
    userAdd: (_, { input }, context) => addUser(context, context.user, input),
    bookmarkAdd: (_, { id, type }, context) => addBookmark(context, context.user, id, type),
    bookmarkDelete: (_, { id }, context) => deleteBookmark(context, context.user, id),
  },
  Subscription: {
    user: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        userEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          userCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default userResolvers;
