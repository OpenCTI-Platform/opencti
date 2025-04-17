import type { Resolvers } from '../../generated/graphql';
import { askSendOtp, verify2fa, verifyOtp } from './auth-domain';

const authResolvers: Resolvers = {
  Query: {},
  Mutation: {
    askSendOtp: (_, { input }, context) => {
      return askSendOtp(context, input);
    },
    verifyOtp: (_, { input }, context) => {
      return verifyOtp(context, input);
    },
    verify2fa: (_, { input }) => {
      return verify2fa(input);
    },
  },
};

export default authResolvers;
