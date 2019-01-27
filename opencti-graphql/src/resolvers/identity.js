import {
  addIdentity,
  identityDelete,
  findAll,
  findById,
  search,
  identityEditContext,
  identityEditField,
  identityAddRelation,
  identityDeleteRelation
} from '../domain/identity';
import { auth } from './wrapper';

const identityResolvers = {
  Query: {
    identity: auth((_, { id }) => findById(id)),
    identities: auth((_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    })
  },
  Identity: {
    __resolveType(obj) {
      if (obj.type) {
        return obj.type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    }
  },
  Mutation: {
    identityEdit: auth((_, { id }, { user }) => ({
      delete: () => identityDelete(id),
      fieldPatch: ({ input }) => identityEditField(user, id, input),
      contextPatch: ({ input }) => identityEditContext(user, id, input),
      relationAdd: ({ input }) => identityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        identityDeleteRelation(user, id, relationId)
    })),
    identityAdd: auth((_, { input }, { user }) => addIdentity(user, input))
  }
};

export default identityResolvers;
