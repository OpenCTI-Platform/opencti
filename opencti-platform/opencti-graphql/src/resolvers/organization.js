import { addOrganization, findAll, findById } from '../domain/organization';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

const organizationResolvers = {
  Query: {
    organization: (_, { id }) => findById(id),
    organizations: (_, args) => findAll(args)
  },
  Mutation: {
    organizationEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    organizationAdd: (_, { input }, { user }) => addOrganization(user, input)
  }
};

export default organizationResolvers;
