import type { Resolvers } from '../../generated/graphql';
import { generateGlobalConfigurationExport } from './globalExport-domain';

const globalExportResolvers: Resolvers = {
  Query: {
    globalConfigurationExport: (_, { entityTypes, selections }, context) => generateGlobalConfigurationExport(context, context.user, entityTypes, selections),
  },
};

export default globalExportResolvers;
