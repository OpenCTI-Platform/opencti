import type { Resolvers } from '../../generated/graphql';
import {
  smtpConfigurationAdd,
  getSmtpConfiguration,
  getSmtpConfigurationById,
  smtpConfigurationDelete,
  smtpConfigurationTest,
  smtpConfigurationUpdate,
} from './smtpConfiguration-domain';

const smtpConfigurationResolvers: Resolvers = {
  Query: {
    smtpConfiguration: (_, __, context) => getSmtpConfiguration(context, context.user!),
    smtpConfigurationById: (_, { id }, context) => getSmtpConfigurationById(context, context.user!, id),
  },
  Mutation: {
    smtpConfigurationAdd: (_, { input }, context) => smtpConfigurationAdd(context, context.user!, input),
    smtpConfigurationUpdate: (_, { id, input }, context) => smtpConfigurationUpdate(context, context.user!, id, input),
    smtpConfigurationDelete: (_, { id }, context) => smtpConfigurationDelete(context, context.user!, id),
    smtpConfigurationTest: (_, { email }, context) => smtpConfigurationTest(context, context.user!, email),
  },
};

export default smtpConfigurationResolvers;
