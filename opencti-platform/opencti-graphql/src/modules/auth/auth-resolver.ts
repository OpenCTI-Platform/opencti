import type { Resolvers } from '../../generated/graphql';
import { askSendToken } from './auth-domain';

const authResolvers: Resolvers = {
  Query: {},
  Mutation: {
    askSendToken: (_, { email }, context) => askSendToken(context, email)
  },
};

export default authResolvers;
