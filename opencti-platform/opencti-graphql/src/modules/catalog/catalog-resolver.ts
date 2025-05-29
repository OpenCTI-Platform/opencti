import { findAll, findById } from './catalog-domain';
import type { Resolvers } from '../../generated/graphql';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { COMPOSER_FF } from './catalog-types';

const catalogResolver: Resolvers = {
  Query: {
    catalog: (_, { id }, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return findById(context, context.user, id);
    },
    catalogs: (_, args, context) => {
      enforceEnableFeatureFlag(COMPOSER_FF);
      return findAll(context, context.user);
    },
  },
};

export default catalogResolver;
