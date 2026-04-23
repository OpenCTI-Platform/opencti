import type { Resolvers } from '../../generated/graphql';
import { getCustomViewsSettings, getCustomViewByIdForDisplay, computeCustomViewPath, findAllCustomViews } from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewDisplay: (_parent, { id }, context) => {
      return getCustomViewByIdForDisplay(context, context.user, id);
    },
    customViewsSettings: (_parent, { entityType }) => {
      return getCustomViewsSettings(entityType);
    },
    customViews: (_parent, { entityType, ...paginationOptions }, context) => {
      return findAllCustomViews(context, context.user, entityType, paginationOptions);
    },
  },
  CustomView: {
    path: (customView) => {
      return computeCustomViewPath(customView);
    },
    targetEntityType: (customView) => {
      return customView.target_entity_type;
    },
  },
  Mutation: {},
};

export default customViewResolver;
