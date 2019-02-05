import {
  addCountry,
  countryDelete,
  findAll,
  findById
} from '../domain/country';
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

const countryResolvers = {
  Query: {
    country: (_, { id }) => findById(id),
    countries: (_, args) => findAll(args)
  },
  Country: {
    createdByRef: (country, args) => createdByRef(country.id, args),
    markingDefinitions: (country, args) => markingDefinitions(country.id, args),
    reports: (country, args) => reports(country.id, args),
    stixRelations: (country, args) => stixRelations(country.id, args),
    editContext: country => fetchEditContext(country.id)
  },
  Mutation: {
    countryEdit: (_, { id }, { user }) => ({
      delete: () => countryDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    countryAdd: (_, { input }, { user }) => addCountry(user, input)
  }
};

export default countryResolvers;
