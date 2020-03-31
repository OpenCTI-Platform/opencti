import { findAll, inferenceEnable, inferenceDisable } from '../domain/inference';

const inferenceResolvers = {
  Query: {
    inferences: () => findAll(),
  },
  Mutation: {
    inferenceEnable: (_, { id }) => inferenceEnable(id),
    inferenceDisable: (_, { id }) => inferenceDisable(id),
  },
};

export default inferenceResolvers;
