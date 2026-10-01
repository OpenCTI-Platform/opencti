import type { Resolvers, ResolversTypes } from '../../generated/graphql';
import { generateGlobalConfigurationExport } from './globalExport-domain';

const globalExportResolvers: Resolvers = {
  Mutation: {
    globalConfigurationExport: async (_, { entityTypes, selections, bundleName }, context) => {
      const file = await generateGlobalConfigurationExport(context, context.user, entityTypes, selections, bundleName);
      return file as unknown as ResolversTypes['File'];
    },
  },
};

export default globalExportResolvers;
