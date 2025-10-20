import { findFiltersRepresentatives } from '../domain/basicObject';
import type { Resolvers } from '../generated/graphql';

const basicObjectResolvers: Resolvers = {
  Query: {
    filtersRepresentatives: (_, { filters }, context) => findFiltersRepresentatives(context, context.user, filters),
  },
  BasicObject: {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (_, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
    metrics(obj) { return obj.metrics ? obj.metrics : []; }
  }
};

export default basicObjectResolvers;
