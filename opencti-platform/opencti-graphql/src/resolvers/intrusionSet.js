import { addIntrusionSet, findAll, findById } from '../domain/intrusionSet';
import {
  createdByRef,
  markingDefinitions,
  reports,
  exports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }) => findById(id),
    intrusionSets: (_, args) => findAll(args)
  },
  IntrusionSet: {
    createdByRef: intrusionSet => createdByRef(intrusionSet.id),
    markingDefinitions: (intrusionSet, args) =>
      markingDefinitions(intrusionSet.id, args),
    reports: (intrusionSet, args) => reports(intrusionSet.id, args),
    exports: (intrusionSet, args) => exports(intrusionSet.id, args),
    stixRelations: (intrusionSet, args) => stixRelations(intrusionSet.id, args),
    editContext: intrusionSet => fetchEditContext(intrusionSet.id)
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
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
