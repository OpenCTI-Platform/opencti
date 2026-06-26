import { findAllDataSanityExecutions, listAllSanityOperations, setForceRun } from './dataSanity-domain';

const dataSanityResolvers = {
  Query: {
    dataSanityOperations: (_: any, __: any, context: any) => listAllSanityOperations(context),
    dataSanityExecutions: (_: any, __: any, context: any) => findAllDataSanityExecutions(context, context.user),
  },
  Mutation: {
    dataSanityOperationRequestRun: (_: any, { operation_name }: { operation_name: string }, context: any) => setForceRun(context, context.user, operation_name),
  },
};

export default dataSanityResolvers;
