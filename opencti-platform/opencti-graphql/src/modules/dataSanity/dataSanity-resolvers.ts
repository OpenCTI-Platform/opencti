import { executeDryRun, findAllDataSanityExecutions, listAllSanityOperations, setForceRun } from './dataSanity-domain';

const dataSanityResolvers = {
  Query: {
    dataSanityOperations: (_: any, __: any, context: any) => listAllSanityOperations(context, context.user),
    dataSanityExecutions: (_: any, __: any, context: any) => findAllDataSanityExecutions(context, context.user),
    dataSanityOperationDryRun: (_: any, { operation_name }: { operation_name: string }, context: any) => executeDryRun(context, operation_name),
  },
  Mutation: {
    dataSanityOperationRequestRun: (_: any, { operation_name }: { operation_name: string }, context: any) => setForceRun(context, context.user, operation_name),
  },
};

export default dataSanityResolvers;
