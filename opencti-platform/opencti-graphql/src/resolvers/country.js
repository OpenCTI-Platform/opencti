import { addCountry, findAll, findById, batchRegion } from '../domain/country';
import {
  stixDomainObjectEditContext,
  stixDomainObjectCleanContext,
  stixDomainObjectEditField,
  stixDomainObjectAddRelation,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
} from '../domain/stixDomainObject';
import { initBatchLoader } from '../database/middleware';

const batchRegionLoader = (user) => initBatchLoader(user, batchRegion);

const countryResolvers = {
  Query: {
    country: (_, { id }, { user }) => findById(user, id),
    countries: (_, args, { user }) => findAll(user, args),
  },
  Country: {
    region: (country, _, { user }) => batchRegionLoader(user).load(country.id),
  },
  Mutation: {
    countryEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    countryAdd: (_, { input }, { user }) => addCountry(user, input),
  },
};

export default countryResolvers;
