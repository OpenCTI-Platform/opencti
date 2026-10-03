import type { Resolvers } from '../../generated/graphql';
import { loadCreator, loadCreators } from '../../database/members';
import {
  deleteIocValidationRequest,
  filterReadableIocs,
  filterReadableSkipped,
  findIocValidationConnectors,
  findIocValidationRequest,
  findIocValidationRequestsPaginated,
  loadRequestConnector,
  loadRequestDeployments,
  loadRequestPlatforms,
  requestIndicatorsValidation,
  updateIocValidationRequestStatus,
} from './iocValidation-domain';
import { emptyResultsSummary, requesterIdOf } from './iocValidation-utils';

const iocValidationResolvers: Resolvers = {
  Query: {
    iocValidationRequest: (_, { id }, context) => findIocValidationRequest(context, context.user!, id) as never,
    iocValidationRequests: (_, args, context) => findIocValidationRequestsPaginated(context, context.user!, args) as never,
    iocValidationConnectors: (_, __, context) => findIocValidationConnectors(context, context.user!),
  },
  IocValidationRequest: {
    creators: (request, _, context) => loadCreators(context, context.user!, request) as never,
    platforms: (request, _, context) => loadRequestPlatforms(context, context.user!, request as never) as never,
    indicators_count: (request) => (request.indicator_ids ?? []).length,
    results_summary: (request) => request.results_summary ?? emptyResultsSummary(),
    iocs: async (request, _, context) => (await filterReadableIocs(context, context.user!, request as never)).iocs as never,
    skipped: (request, _, context) => filterReadableSkipped(context, context.user!, request as never) as never,
    deployments: (request, _, context) => loadRequestDeployments(context, context.user!, request as never) as never,
    connector: (request, _, context) => loadRequestConnector(context, context.user!, request as never) as never,
    requested_by: (request, _, context) => {
      const requesterId = requesterIdOf(request as never);
      return (requesterId ? loadCreator(context, context.user!, requesterId) : null) as never;
    },
  },
  Mutation: {
    indicatorsRequestValidation: (_, args, context) => requestIndicatorsValidation(context, context.user!, args) as never,
    iocValidationRequestStatusUpdate: (_, { id, input }, context) => updateIocValidationRequestStatus(context, context.user!, id, input) as never,
    iocValidationRequestDelete: (_, { id }, context) => deleteIocValidationRequest(context, context.user!, id),
  },
};

export default iocValidationResolvers;
