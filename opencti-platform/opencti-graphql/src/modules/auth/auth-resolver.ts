import type { Resolvers } from '../../generated/graphql';
import { askSendOtp } from './auth-domain';

const authResolvers: Resolvers = {
  Query: {},
  Mutation: {
    askSendOtp: (_, { input }, context) => {
      return askSendOtp(context, input);
    }
  },
};

export default authResolvers;
