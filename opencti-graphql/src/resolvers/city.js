import { addCity, cityDelete, findAll, findById } from '../domain/city';
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
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const cityResolvers = {
  Query: {
    city: (_, { id }) => findById(id),
    cities: (_, args) => findAll(args)
  },
  City: {
    createdByRef: (city, args) => createdByRef(city.id, args),
    markingDefinitions: (city, args) => markingDefinitions(city.id, args),
    reports: (city, args) => reports(city.id, args),
    exports: (city, args) => exports(city.id, args),
    stixRelations: (city, args) => stixRelations(city.id, args),
    editContext: city => fetchEditContext(city.id)
  },
  Mutation: {
    cityEdit: (_, { id }, { user }) => ({
      delete: () => cityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    cityAdd: (_, { input }, { user }) => addCity(user, input)
  }
};

export default cityResolvers;
