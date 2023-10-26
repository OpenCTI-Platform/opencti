import { addCountry, batchRegion, findAll, findById } from '../domain/country';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { batchLoader } from '../database/middleware';

const batchRegionLoader = batchLoader(batchRegion);

const countryResolvers = {
  Query: {
    country: (_, { id }, context) => findById(context, context.user, id),
    countries: (_, args, context) => findAll(context, context.user, args),
  },
  Country: {
    region: (country, _, context) => batchRegionLoader.load(country.id, context, context.user),
  },
  Mutation: {
    countryEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    countryAdd: (_, { input }, context) => addCountry(context, context.user, input),
  },
};

export default countryResolvers;
