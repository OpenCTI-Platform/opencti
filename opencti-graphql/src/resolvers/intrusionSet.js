import {
  addIntrusionSet,
  intrusionSetDelete,
  findAll,
  findById
} from '../domain/intrusionSet';
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
import { fetchEditContext } from '../database/redis';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }) => findById(id),
    intrusionSets: (_, args) => findAll(args)
  },
  IntrusionSet: {
    createdByRef: (intrusionSet, args) => createdByRef(intrusionSet.id, args),
    markingDefinitions: (intrusionSet, args) =>
      markingDefinitions(intrusionSet.id, args),
    reports: (intrusionSet, args) => reports(intrusionSet.id, args),
    stixRelations: (intrusionSet, args) => stixRelations(intrusionSet.id, args),
    editContext: intrusionSet => fetchEditContext(intrusionSet.id)
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, { user }) => ({
      delete: () => intrusionSetDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    intrusionSetAdd: (_, { input }, { user }) => addIntrusionSet(user, input)
  }
};

export default intrusionSetResolvers;
