import { addCity, findAll, findById, country } from '../domain/city';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainEntity';

const cityResolvers = {
  Query: {
    city: (_, { id }) => findById(id),
    cities: (_, args) => findAll(args),
  },
  City: {
    country: (city) => country(city.id),
  },
  Mutation: {
    cityEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    cityAdd: (_, { input }, { user }) => addCity(user, input),
  },
};

export default cityResolvers;
