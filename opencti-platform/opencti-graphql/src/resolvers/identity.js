import { addIdentity, findAll, findById } from '../domain/identity';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

const identityResolvers = {
  Query: {
    identity: (_, { id }) => findById(id),
    identities: (_, args) => findAll(args)
  },
  Identity: {
    // eslint-disable-next-line no-underscore-dangle
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) =>
          letter.toUpperCase()
        );
      }
      return 'Unknown';
    },
    createdByRef: identity => createdByRef(identity.id),
    markingDefinitions: (identity, args) =>
      markingDefinitions(identity.id, args),
    reports: (identity, args) => reports(identity.id, args),
    stixRelations: (identity, args) => stixRelations(identity.id, args)
  },
  Mutation: {
    identityEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
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
