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
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const countryResolvers = {
  Query: {
    country: auth((_, { id }) => findById(id)),
    countries: auth((_, args) => findAll(args))
  },
  Country: {
    createdByRef: (country, args) => createdByRef(country.id, args),
    markingDefinitions: (country, args) =>
      markingDefinitions(country.id, args),
    reports: (country, args) => reports(country.id, args),
    stixRelations: (country, args) => stixRelations(country.id, args),
    editContext: auth(country => fetchEditContext(country.id))
  },
  Mutation: {
    countryEdit: auth((_, { id }, { user }) => ({
      delete: () => countryDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    countryAdd: auth((_, { input }, { user }) => addCountry(user, input))
  }
};

export default countryResolvers;
