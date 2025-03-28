import type { Resolvers } from '../../generated/graphql';
import { askSendOtp, verifyOtp } from './auth-domain';

const authResolvers: Resolvers = {
  Query: {},
  Mutation: {
    askSendOtp: (_, { input }, context) => {
      return askSendOtp(context, input);
    },
    verifyOtp: (_, { input }, context) => {
      return verifyOtp(context, input);
    },
  },
};

export default authResolvers;
