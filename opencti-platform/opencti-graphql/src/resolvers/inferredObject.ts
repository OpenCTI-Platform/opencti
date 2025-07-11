import type { Resolvers } from '../generated/graphql';
import { createInternalInferredEntity, createInternalInferredRelation } from '../domain/inferredObject';

const inferredObjectResolvers: Resolvers = {
  Mutation: {
    inferredRelationAdd: (_, { jsonInput }, context) => createInternalInferredRelation(context, context.user, jsonInput),
    inferredEntityAdd: (_, { jsonInput }, context) => createInternalInferredEntity(context, context.user, jsonInput),
  },
};

export default inferredObjectResolvers;
