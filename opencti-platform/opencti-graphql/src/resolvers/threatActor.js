import { addThreatActor, findAll, findById } from '../domain/threatActor';
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

const threatActorResolvers = {
  Query: {
    threatActor: (_, { id }) => findById(id),
    threatActors: (_, args) => findAll(args)
  },
  ThreatActor: {
    createdByRef: threatActor => createdByRef(threatActor.id),
    markingDefinitions: (threatActor, args) =>
      markingDefinitions(threatActor.id, args),
    reports: (threatActor, args) => reports(threatActor.id, args),
    exports: (threatActor, args) => exports(threatActor.id, args),
    stixRelations: (threatActor, args) => stixRelations(threatActor.id, args),
    editContext: threatActor => fetchEditContext(threatActor.id)
  },
  Mutation: {
    threatActorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    threatActorAdd: (_, { input }, { user }) => addThreatActor(user, input)
  }
};

export default threatActorResolvers;
