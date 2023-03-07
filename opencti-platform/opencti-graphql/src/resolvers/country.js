import { addCountry, findAll, findById, batchRegion } from '../domain/country';
import {
  stixDomainObjectEditContext,
  stixDomainObjectCleanContext,
  stixDomainObjectEditField,
  stixDomainObjectAddRelation,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
} from '../domain/stixDomainObject';
import { batchLoader } from '../database/middleware';
import { buildRefRelationKey } from '../schema/general';
import { RELATION_CREATED_BY } from '../schema/stixRefRelationship';

const batchRegionLoader = batchLoader(batchRegion);

const countryResolvers = {
  Query: {
    country: (_, { id }, context) => findById(context, context.user, id),
    countries: (_, args, context) => findAll(context, context.user, args),
  },
  Country: {
    region: (country, _, context) => batchRegionLoader.load(country.id, context, context.user),
  },
  CountriesFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    creator: 'creator_id',
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
