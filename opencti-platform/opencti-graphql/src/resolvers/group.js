import {
  addGroup,
  groupDelete,
  findAll,
  findById,
  members,
  permissions,
  groupEditField,
  groupDeleteRelation,
  groupAddRelation,
  groupCleanContext,
  groupEditContext,
} from '../domain/group';
import { fetchEditContext } from '../database/redis';

const groupResolvers = {
  Query: {
    group: (_, { id }) => findById(id),
    groups: (_, args) => findAll(args),
  },
  Group: {
    members: (group) => members(group.id),
    permissions: (group) => permissions(group.id),
    editContext: (group) => fetchEditContext(group.id),
  },
  Mutation: {
    groupEdit: (_, { id }, { user }) => ({
      delete: () => groupDelete(user, id),
      fieldPatch: ({ input }) => groupEditField(user, id, input),
      contextPatch: ({ input }) => groupEditContext(user, id, input),
      contextClean: () => groupCleanContext(user, id),
      relationAdd: ({ input }) => groupAddRelation(user, id, input),
      relationDelete: ({ relationId }) => groupDeleteRelation(user, id, relationId),
    }),
    groupAdd: (_, { input }, { user }) => addGroup(user, input),
  },
};

export default groupResolvers;
