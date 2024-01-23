import { addCity, locatedAtCountry, findAll, findById } from '../domain/city';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const cityResolvers = {
  Query: {
    city: (_, { id }, context) => findById(context, context.user, id),
    cities: (_, args, context) => findAll(context, context.user, args),
  },
  City: {
    country: (city, _, context) => locatedAtCountry(context, context.user, city.id),
  },
  Mutation: {
    cityEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    cityAdd: (_, { input }, context) => addCity(context, context.user, input),
  },
};

export default cityResolvers;
