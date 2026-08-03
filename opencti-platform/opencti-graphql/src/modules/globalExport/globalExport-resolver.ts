import type { Resolvers } from '../../generated/graphql';
import { generateGlobalConfigurationExport } from './globalExport-domain';

const globalExportResolvers: Resolvers = {
  Query: {
    globalConfigurationExport: (_, { categories }, context) => generateGlobalConfigurationExport(context, context.user, categories),
  },
};

export default globalExportResolvers;
