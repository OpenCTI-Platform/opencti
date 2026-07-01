import { executeDryRun, findAllDataSanityExecutions, listAllSanityOperations, setForceRun } from './dataSanity-domain';
import { getDataSanityConfiguration, updateMaintenancePlanning } from './dataSanityConfiguration-domain';
import type { MaintenancePlanning } from './dataSanityConfiguration-types';

const dataSanityResolvers = {
  Query: {
    dataSanityOperations: (_: any, __: any, context: any) => listAllSanityOperations(context, context.user),
    dataSanityExecutions: (_: any, __: any, context: any) => findAllDataSanityExecutions(context, context.user),
    dataSanityOperationDryRun: (_: any, { operation_name }: { operation_name: string }, context: any) => executeDryRun(context, operation_name),
    dataSanityConfiguration: (_: any, __: any, context: any) => getDataSanityConfiguration(context, context.user),
  },
  Mutation: {
    dataSanityOperationRequestRun: (_: any, { operation_name }: { operation_name: string }, context: any) => setForceRun(context, context.user, operation_name),
    dataSanityUpdateMaintenancePlanning: (_: any, { planning, timezone_offset }:
    { planning: MaintenancePlanning; timezone_offset: number }, context: any) => updateMaintenancePlanning(context, context.user, planning, timezone_offset),
  },
};

export default dataSanityResolvers;
