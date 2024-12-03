import type { Resolvers } from '../../generated/graphql';

const templateResolvers: Resolvers = {
  Query: {
  },
  Template: {
  },
  Mutation: {
    templateAdd: (_, { input }, context) => {
    },
    templateDelete: (_, { id }, context) => {
    },
    templateFieldPatch: (_, { id, input }, context) => {
    },
  },
};

export default templateResolvers;
