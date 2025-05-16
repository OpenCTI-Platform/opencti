import type { Resolvers } from '../../generated/graphql';
import { askSendOtp, changePassword, verifyMfa, verifyOtp } from './auth-domain';

const authResolvers: Resolvers = {
  Query: {},
  Mutation: {
    askSendOtp: (_, { input }, context) => {
      return askSendOtp(context, input);
    },
    verifyOtp: (_, { input }) => {
      return verifyOtp(input);
    },
    verifyMfa: (_, { input }, context) => {
      return verifyMfa(context, input);
    },
    changePassword: (_, { input }, context) => {
      return changePassword(context, input);
    },
  },
};

export default authResolvers;
