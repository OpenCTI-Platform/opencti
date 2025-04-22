import type { Resolvers } from '../../generated/graphql';
import { askSendOtp, changePassword, verify2fa, verifyOtp } from './auth-domain';

const authResolvers: Resolvers = {
  Query: {},
  Mutation: {
    askSendOtp: (_, { input }, context) => {
      return askSendOtp(context, input);
    },
    verifyOtp: (_, { input }) => {
      return verifyOtp(input);
    },
    verify2fa: (_, { input }) => {
      return verify2fa(input);
    },
    changePassword: (_, { input }, context) => {
      return changePassword(context, input);
    },
  },
};

export default authResolvers;
