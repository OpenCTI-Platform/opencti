import type { Resolvers } from '../../generated/graphql';
import { getSmtpConfiguration, smtpConfigurationDelete, smtpConfigurationEdit, smtpConfigurationTest } from './smtpConfiguration-domain';

const smtpConfigurationResolvers: Resolvers = {
  Query: {
    smtpConfiguration: (_, __, context) => getSmtpConfiguration(context, context.user!),
  },
  Mutation: {
    smtpConfigurationEdit: (_, { input }, context) => smtpConfigurationEdit(context, context.user!, input),
    smtpConfigurationDelete: (_, __, context) => smtpConfigurationDelete(context, context.user!),
    smtpConfigurationTest: (_, { email }, context) => smtpConfigurationTest(context, context.user!, email),
  },
};

export default smtpConfigurationResolvers;
