import type { Resolvers } from '../../generated/graphql';
import {
  addCustomView,
  editCustomView,
  getCustomViewsSettings,
  findCustomViewById,
  computeCustomViewPath,
  findAllCustomViews,
  customViewImportWidgetConfiguration,
  exportCustomViewWidget,
  duplicateCustomView,
} from './customView-domain';

const customViewResolver: Resolvers = {
  Query: {
    customViewsSettings: (_parent, { entityType }) => {
      return getCustomViewsSettings(entityType);
    },
    customViews: (_parent, { entityType, ...paginationOptions }, context) => {
      return findAllCustomViews(context, context.user, entityType, paginationOptions);
    },
    customView: (_parent, { id }, context) => {
      return findCustomViewById(context, context.user, id);
    },
  },
  CustomView: {
    path: (customView) => {
      return computeCustomViewPath(customView);
    },
    targetEntityType: (customView) => {
      return customView.target_entity_type;
    },
    toWidgetExport: (customView, { widgetId }, context) => {
      return exportCustomViewWidget(context, context.user, customView, widgetId);
    },
  },
  Mutation: {
    customViewAdd: (_, { input }, context) => {
      return addCustomView(context, context.user, input);
    },
    customViewEdit: (_, { id, input }, context) => {
      return editCustomView(context, context.user, id, input);
    },
    customViewWidgetConfigurationImport: (_, { id, input }, context) => {
      return customViewImportWidgetConfiguration(context, context.user, id, input);
    },
    customViewDuplicate: (_parent, { input }, context) => {
      return duplicateCustomView(context, context.user, input);
    },
  },
};

export default customViewResolver;
