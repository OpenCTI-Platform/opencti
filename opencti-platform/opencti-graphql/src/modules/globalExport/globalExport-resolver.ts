import type { Resolvers } from '../../generated/graphql';
import { generateGlobalConfigurationExport } from './globalExport-domain';

const globalExportResolvers: Resolvers = {
  Query: {
    globalConfigurationExport: (_, { entityTypes }, context) => generateGlobalConfigurationExport(context, context.user, entityTypes),
  },
};

export default globalExportResolvers;
