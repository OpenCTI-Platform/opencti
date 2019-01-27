import {
  addThreatActor,
  threatActorDelete,
  findAll,
  findById
} from '../domain/threatActor';
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
import { auth } from './wrapper';

const threatActorResolvers = {
  Query: {
    threatActor: auth((_, { id }) => findById(id)),
    threatActors: auth((_, args) => findAll(args))
  },
  ThreatActor: {
    createdByRef: (threatActor, args) => createdByRef(threatActor.id, args),
    markingDefinitions: (threatActor, args) => markingDefinitions(threatActor.id, args),
    reports: (threatActor, args) => reports(threatActor.id, args),
    stixRelations: (threatActor, args) => stixRelations(threatActor.id, args),
    editContext: auth(threatActor => fetchEditContext(threatActor.id))
  },
  Mutation: {
    threatActorEdit: auth((_, { id }, { user }) => ({
      delete: () => threatActorDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    threatActorAdd: auth((_, { input }, { user }) =>
      addThreatActor(user, input)
    )
  }
};

export default threatActorResolvers;
