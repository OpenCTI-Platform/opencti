import {
  addGroup,
  groupDelete,
  findAll,
  findById,
  members,
  permissions,
  groupEditContext,
  groupEditField,
  groupAddRelation,
  groupDeleteRelation,
} from '../domain/group';
import { fetchEditContext } from '../database/redis';
import { admin, auth } from './wrapper';

const groupResolvers = {
  Query: {
    group: auth((_, { id }) => findById(id)),
    groups: auth((_, args) => findAll(args))
  },
  Group: {
    members: (group, args) => members(group.id, args),
    permissions: (group, args) => permissions(group.id, args),
    editContext: admin(group => fetchEditContext(group.id))
  },
  Mutation: {
    groupEdit: admin((_, { id }, { user }) => ({
      delete: () => groupDelete(id),
      fieldPatch: ({ input }) => groupEditField(user, id, input),
      contextPatch: ({ input }) => groupEditContext(user, id, input),
      relationAdd: ({ input }) => groupAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        groupDeleteRelation(user, id, relationId)
    })),
    groupAdd: admin((_, { input }, { user }) => addGroup(user, input))
  }
};

export default groupResolvers;
