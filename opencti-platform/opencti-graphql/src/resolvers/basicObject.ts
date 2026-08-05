import { findFiltersRepresentatives } from '../domain/basicObject';
import type { Resolvers } from '../generated/graphql';

const basicObjectResolvers: Resolvers = {
  Query: {
    filtersRepresentatives: (_, { filters, isMeValueForbidden }, context) =>
      findFiltersRepresentatives(context, context.user, filters, { isMeValueForbidden }),
  },
  BasicObject: {
    // @ts-expect-error obj is typed generically, entity_type narrowing is not inferred
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (_, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
    parent_types(obj) {
      return obj.parent_types.filter((t) => t);
    },
    metrics(obj) {
      return obj.metrics ? obj.metrics : [];
    },
  },
};

export default basicObjectResolvers;
