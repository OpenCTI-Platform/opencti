import {
  addIdentity,
  identityDelete,
  findAll,
  findById,
  search
} from '../domain/identity';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';

const identityResolvers = {
  Query: {
    identity: (_, { id }) => findById(id),
    identities: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    }
  },
  Identity: {
    __resolveType(obj) {
      if (obj.type) {
        return obj.type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    },
    createdByRef: (identity, args) => createdByRef(identity.id, args),
    markingDefinitions: (identity, args) =>
      markingDefinitions(identity.id, args),
    reports: (identity, args) => reports(identity.id, args),
    stixRelations: (identity, args) => stixRelations(identity.id, args)
  },
  Mutation: {
    identityEdit: (_, { id }, { user }) => ({
      delete: () => identityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    identityAdd: (_, { input }, { user }) => addIdentity(user, input)
  }
};

export default identityResolvers;
