import {
  addGroup,
  groupDelete,
  findAll,
  findById,
  members,
  permissions
} from '../domain/group';
import {
  createdByRef,
  exports,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const groupResolvers = {
  Query: {
    group: (_, { id }) => findById(id),
    groups: (_, args) => findAll(args)
  },
  Group: {
    createdByRef: (group, args) => createdByRef(group.id, args),
    members: (group, args) => members(group.id, args),
    exports: (group, args) => exports(group.id, args),
    permissions: (group, args) => permissions(group.id, args),
    editContext: group => fetchEditContext(group.id)
  },
  Mutation: {
    groupEdit: (_, { id }, { user }) => ({
      delete: () => groupDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    groupAdd: (_, { input }, { user }) => addGroup(user, input)
  }
};

export default groupResolvers;
