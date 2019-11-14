import { addThreatActor, findAll, findById } from '../domain/threatActor';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';

const threatActorResolvers = {
  Query: {
    threatActor: (_, { id }) => findById(id),
    threatActors: (_, args) => findAll(args)
  },
  Mutation: {
    threatActorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    threatActorAdd: (_, { input }, { user }) => addThreatActor(user, input)
  }
};

export default threatActorResolvers;
