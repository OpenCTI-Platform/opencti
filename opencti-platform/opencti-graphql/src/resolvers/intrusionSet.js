import { addIntrusionSet, findAll, findById } from '../domain/intrusionSet';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }) => findById(id),
    intrusionSets: (_, args) => findAll(args)
  },
  IntrusionSetsOrdering: {
    markingDefinitions: 'object_marking_refs.definition',
    tags: 'tagged.value'
  },
  IntrusionSetsFilter: {
    tags: 'tagged.internal_id_key'
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    intrusionSetAdd: (_, { input }, { user }) => addIntrusionSet(user, input)
  }
};

export default intrusionSetResolvers;
