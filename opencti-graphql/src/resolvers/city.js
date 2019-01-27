import {
  addCity,
  cityDelete,
  findAll,
  findById
} from '../domain/city';
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

const cityResolvers = {
  Query: {
    city: auth((_, { id }) => findById(id)),
    cities: auth((_, args) => findAll(args))
  },
  City: {
    createdByRef: (city, args) => createdByRef(city.id, args),
    markingDefinitions: (city, args) =>
      markingDefinitions(city.id, args),
    reports: (city, args) => reports(city.id, args),
    stixRelations: (city, args) => stixRelations(city.id, args),
    editContext: auth(city => fetchEditContext(city.id))
  },
  Mutation: {
    cityEdit: auth((_, { id }, { user }) => ({
      delete: () => cityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    cityAdd: auth((_, { input }, { user }) => addCity(user, input))
  }
};

export default cityResolvers;
