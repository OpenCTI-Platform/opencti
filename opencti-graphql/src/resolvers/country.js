import {
  addCountry,
  countryDelete,
  findAll,
  findById,
  markingDefinitions,
  countryEditContext,
  countryEditField,
  countryAddRelation,
  countryDeleteRelation
} from '../domain/country';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const countryResolvers = {
  Query: {
    country: auth((_, { id }) => findById(id)),
    countries: auth((_, args) => findAll(args))
  },
  Country: {
    markingDefinitions: (country, args) => markingDefinitions(country.id, args),
    stixRelations: (country, args) => stixRelations(country.id, args),
    editContext: auth(country => fetchEditContext(country.id))
  },
  Mutation: {
    countryEdit: auth((_, { id }, { user }) => ({
      delete: () => countryDelete(id),
      fieldPatch: ({ input }) => countryEditField(user, id, input),
      contextPatch: ({ input }) => countryEditContext(user, id, input),
      relationAdd: ({ input }) => countryAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        countryDeleteRelation(user, id, relationId)
    })),
    countryAdd: auth((_, { input }, { user }) => addCountry(user, input))
  }
};

export default countryResolvers;
