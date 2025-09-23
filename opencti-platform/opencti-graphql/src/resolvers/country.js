import { addCountry, findCountryPaginated, findById, locatedAtRegion } from '../domain/country';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const countryResolvers = {
  Query: {
    country: (_, { id }, context) => findById(context, context.user, id),
    countries: (_, args, context) => findCountryPaginated(context, context.user, args),
  },
  Country: {
    region: (country, _, context) => locatedAtRegion(context, context.user, country.id),
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
