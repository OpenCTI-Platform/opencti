import { BUS_TOPICS, ENABLED_DEMO_MODE } from '../config/conf';
import { internalLoadById } from '../database/middleware-loader';
import { fetchEditContext } from '../database/redis';
import { applicationSession, findSessions, findUserSessions, killSession, killUserSessions } from '../database/session';
import { addRole } from '../domain/grant';
import {
  addBookmark,
  addUser,
  assignOrganizationToUser,
  bookmarks,
  buildCompleteUser,
  deleteBookmark,
  findMembersPaginated,
  findAllSystemMemberPaginated,
  findAssignees,
  findById,
  findCapabilities,
  findCreators,
  findDefaultDashboards,
  findParticipants,
  findRoleById,
  findRoles,
  getUserEffectiveConfidenceLevel,
  groupRolesPaginated,
  meEditField,
  otpUserActivation,
  otpUserDeactivation,
  otpUserGeneration,
  otpUserLogin,
  roleAddRelation,
  roleCapabilities,
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
  userGroupsPaginated,
  userIdDeleteRelation,
  userOrganizationsPaginated,
  userOrganizationsPaginatedWithoutInferences,
  userRoles,
  sendEmailToUser,
  findUserPaginated,
  sessionLogin,
} from '../domain/user';
import { subscribeToInstanceEvents, subscribeToUserEvents } from '../graphql/subscriptionWrapper';
import { publishUserAction } from '../listener/UserActionListener';
import { findById as findDraftById } from '../modules/draftWorkspace/draftWorkspace-domain';
import { addUserToken, revokeUserToken, revokeUserTokenByAdmin, addUserTokenByAdmin } from '../modules/user/user-domain';
import { findById as findWorskpaceById } from '../modules/workspace/workspace-domain';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { REDACTED_USER } from '../utils/access';
import { getNotifiers } from '../modules/notifier/notifier-domain';
import { RELATION_HAS_CAPABILITY_IN_DRAFT } from '../schema/internalRelationship';
import { loadCreator } from '../database/members';
import { issueConnectorJWT } from '../database/repository';

const userResolvers = {
  Query: {
    me: (_, __, context) => context.user,
    user: (_, { id }, context) => findById(context, context.user, id),
    otpGeneration: (_, __, context) => otpUserGeneration(context.user),
    users: (_, args, context) => findUserPaginated(context, context.user, args),
    role: (_, { id }, context) => findRoleById(context, context.user, id),
    roles: (_, args, context) => findRoles(context, context.user, args),
    creators: (_, args, context) => findCreators(context, context.user, args),
    assignees: (_, args, context) => findAssignees(context, context.user, args),
    participants: (_, args, context) => findParticipants(context, context.user, args),
    members: (_, args, context) => findMembersPaginated(context, context.user, args),
    systemMembers: () => findAllSystemMemberPaginated(),
    sessions: () => findSessions(),
    capabilities: (_, args, context) => findCapabilities(context, context.user, args),
    capabilitiesInDraft: (_, args, context) => findCapabilities(context, context.user, args, RELATION_HAS_CAPABILITY_IN_DRAFT),
    bookmarks: (_, args, context) => bookmarks(context, context.user, args),
  },
  User: {
    roles: (current, args, context) => userRoles(context, context.user, current.id, args),
    groups: (current, args, context) => userGroupsPaginated(context, context.user, current.id, args),
    objectOrganization: (current, args, context) => userOrganizationsPaginated(context, context.user, current.id, args),
    objectAssignedOrganization: (current, args, context) => userOrganizationsPaginatedWithoutInferences(context, context.user, current.id, args),
    editContext: (current) => fetchEditContext(current.id),
    sessions: (current) => findUserSessions(current.id),
    effective_confidence_level: (current, _, context) => context.batch.userEffectiveConfidenceBatchLoader.load(current),
    personal_notifiers: (current, _, context) => getNotifiers(context, context.user, current.personal_notifiers),
    api_tokens: async (current, _, context) => context.batch.tokenBatchLoader.load(current),
  },
  Member: {
    name: (current, _, context) => {
      if (current.entity_type !== ENTITY_TYPE_USER) {
        return current.name;
      }
      return (ENABLED_DEMO_MODE && context.user.id !== current.id) ? REDACTED_USER.name : current.name;
    },
    effective_confidence_level: (current, _, context) => {
      if (current.entity_type === ENTITY_TYPE_USER) {
        return getUserEffectiveConfidenceLevel(current, context);
      }
      return null;
    },
  },
  MeUser: {
    language: (current) => current.language ?? 'auto',
    unit_system: (current) => current.unit_system ?? 'auto',
    submenu_show_icons: (current) => current.submenu_show_icons ?? false,
    submenu_auto_collapse: (current) => current.submenu_auto_collapse ?? true,
    monochrome_labels: (current) => current.monochrome_labels ?? false,
    groups: (current, args, context) => userGroupsPaginated(context, context.user, current.id, args),
    objectOrganization: (current, args, context) => userOrganizationsPaginated(context, context.user, current.id, args),
    default_dashboards: (current, _, context) => findDefaultDashboards(context, context.user, current),
    default_dashboard: (current, _, context) => findWorskpaceById(context, context.user, current.default_dashboard),
    draftContext: (current, _, context) => findDraftById(context, context.user, current.draft_context),
    effective_confidence_level: (current, _, context) => getUserEffectiveConfidenceLevel(current, context),
    personal_notifiers: (current, _, context) => getNotifiers(context, context.user, current.personal_notifiers),
    api_tokens: async (current, _, context) => context.batch.tokenBatchLoader.load(current),
  },
  UserSession: {
    user: (session, _, context) => loadCreator(context, context.user, session.user_id),
  },
  Role: {
    editContext: (role) => fetchEditContext(role.id),
    capabilities: (role, _, context) => roleCapabilities(context, context.user, role.id),
    capabilitiesInDraft: (role, _, context) => roleCapabilities(context, context.user, role.id, RELATION_HAS_CAPABILITY_IN_DRAFT),
  },
  Group: {
    roles: (group, args, context) => groupRolesPaginated(context, context.user, group.id, args),
  },
  EffectiveConfidenceLevelSourceObject: {
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
    token: async (_, { input }, context) => sessionLogin(context, input),
    connectorJWT: () => issueConnectorJWT(),
    sessionKill: async (_, { id }, context) => {
      const { store } = applicationSession;
      const userSessionId = id.split(store.prefix)[1]; // Prefix must be removed on this case
      const kill = await killSession(userSessionId);
      if (!kill?.session?.user) return id;
      const { user } = kill.session;
      const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.name : user.user_email;
      await publishUserAction({
        user: context.user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `kills \`specific session\` for user \`${actionEmail}\``,
        context_data: { id: user.id, entity_type: ENTITY_TYPE_USER, input: { user_id: user.id, session_id: kill.sessionId } },
      });
      return id;
    },
    otpUserDeactivation: (_, { id }, context) => otpUserDeactivation(context, context.user, id),
    userSessionsKill: async (_, { id }, context) => {
      const user = await internalLoadById(context, context.user, id);
      if (!user) return [];
      const sessions = await killUserSessions(id);
      const sessionIds = sessions.map((s) => s.sessionId);
      const actionEmail = ENABLED_DEMO_MODE ? REDACTED_USER.name : user.user_email;
      await publishUserAction({
        user: context.user,
        event_type: 'mutation',
        event_scope: 'update',
        event_access: 'administration',
        message: `kills \`all sessions\` for user \`${actionEmail}\``,
        context_data: { id: user.id, entity_type: ENTITY_TYPE_USER, input: { user_id: id } },
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
      relationAdd: ({ input }) => userAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => {
        return userIdDeleteRelation(context, context.user, id, toId, relationshipType);
      },
      organizationAdd: ({ organizationId }) => assignOrganizationToUser(context, context.user, id, organizationId),
      organizationDelete: ({ organizationId }) => userDeleteOrganizationRelation(context, context.user, id, organizationId),
    }),
    meEdit: (_, { input, password }, context) => meEditField(context, context.user, context.user.id, input, password),
    userAdd: (_, { input }, context) => addUser(context, context.user, input),
    bookmarkAdd: (_, { id, type }, context) => addBookmark(context, context.user, id, type),
    bookmarkDelete: (_, { id }, context) => deleteBookmark(context, context.user, id),
    sendUserMail: (_, { input }, context) => {
      return sendEmailToUser(context, context.user, input);
    },
    userTokenAdd: (_, { input }, context) => addUserToken(context, context.user, input),
    userTokenRevoke: async (_, { id }, context) => revokeUserToken(context, context.user, id),
    userAdminTokenRevoke: async (_, { userId, id }, context) => revokeUserTokenByAdmin(context, context.user, userId, id),
    userAdminTokenAdd: async (_, { userId, input }, context) => addUserTokenByAdmin(context, context.user, userId, input),
  },
  Subscription: {
    me: {
      resolve: /* v8 ignore next */ (payload, _, context) => {
        return buildCompleteUser(context, payload.instance);
      },
      subscribe: /* v8 ignore next */ (_, __, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_USER];
        return subscribeToUserEvents(context, [bus.EDIT_TOPIC]);
      },
    },
    user: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => userEditContext(context, context.user, id);
        const cleanFn = () => userCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_USER];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_USER, preFn, cleanFn });
      },
    },
  },
};

export default userResolvers;
