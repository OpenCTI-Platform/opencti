import type { Resolvers } from '../../generated/graphql';
import { getSmtpConfigurationForAdmin, smtpConfigurationEdit, smtpConfigurationTest } from './smtpConfiguration-domain';

const smtpConfigurationResolvers: Resolvers = {
  Query: {
    smtpConfiguration: (_, __, context) => getSmtpConfigurationForAdmin(context, context.user!),
  },
  Mutation: {
    smtpConfigurationEdit: (_, { input }, context) => smtpConfigurationEdit(context, context.user!, input),
    smtpConfigurationTest: (_, { email }, context) => smtpConfigurationTest(context, context.user!, email),
  },
};

export default smtpConfigurationResolvers;
