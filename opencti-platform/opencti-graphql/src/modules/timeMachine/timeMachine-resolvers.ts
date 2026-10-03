import type { Resolvers } from '../../generated/graphql';
import { publishUserAction } from '../../listener/UserActionListener';
import { ENTITY_TYPE_USER_VISIT, type LandscapeDiffInputData, type LandscapeDiffState } from './timeMachine-types';
import { entitiesSinceLastVisit, entityAsOf, entityDiff, entityTimeMachineTimeline, purgeUserVisits, recordEntityVisit } from './timeMachine-domain';
import { findLandscapeDiff, landscapeDiffSummary, runLandscapeDiff } from './landscapeDiff-domain';
import { addChangeDigestTrigger } from './timeMachine-triggers';

const toLandscapeDiff = (state: LandscapeDiffState | null) => {
  if (!state) return null;
  return {
    ...state,
    from: state.input.from,
    to: state.input.to,
    group_by: state.input.group_by ?? 'entity_type',
    filters: state.input.filters ?? null,
    saved_filter_id: state.input.saved_filter_id ?? null,
    custom_view_id: state.input.custom_view_id ?? null,
  };
};

const timeMachineResolvers: Resolvers = {
  Query: {
    entityAsOf: (_, { id, date }, context) => entityAsOf(context, context.user, id, date) as any,
    entityDiff: (_, { id, from, to }, context) => entityDiff(context, context.user, id, from, to) as any,
    entityTimeMachineTimeline: (_, { id }, context) => entityTimeMachineTimeline(context, context.user, id) as any,
    entitiesSinceLastVisit: (_, { ids }, context) => entitiesSinceLastVisit(context, context.user, ids) as any,
    landscapeDiff: async (_, { id }, context) => toLandscapeDiff(await findLandscapeDiff(context, context.user, id)) as any,
    landscapeDiffSummary: (_, { input }, context) => landscapeDiffSummary(context, context.user, input as LandscapeDiffInputData) as any,
  },
  Mutation: {
    entityVisitRecord: (_, { id }, context) => recordEntityVisit(context, context.user, id) as any,
    userVisitsPurge: (_, __, context) => purgeUserVisits(context, context.user),
    userVisitsPurgeForUser: async (_, { userId }, context) => {
      const deleted = await purgeUserVisits(context, context.user, userId);
      await publishUserAction({
        user: context.user,
        event_type: 'mutation',
        event_scope: 'delete',
        event_access: 'administration',
        message: `purges \`${deleted}\` last visit markers of a user`,
        context_data: { id: userId, entity_type: ENTITY_TYPE_USER_VISIT, input: { user_id: userId, deleted } },
      });
      return deleted;
    },
    landscapeDiffRun: async (_, { input }, context) => toLandscapeDiff(await runLandscapeDiff(context, context.user, input as LandscapeDiffInputData)) as any,
    triggerKnowledgeChangeDigestAdd: (_, { input }, context) => addChangeDigestTrigger(context, context.user, input) as any,
  },
};

export default timeMachineResolvers;
