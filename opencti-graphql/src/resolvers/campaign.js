import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addCampaign,
  campaignDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  reports,
  campaignEditContext,
  campaignEditField,
  campaignAddRelation,
  campaignDeleteRelation,
  campaignCleanContext
} from '../domain/campaign';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const campaignResolvers = {
  Query: {
    campaign: auth((_, { id }) => findById(id)),
    campaigns: auth((_, args) => findAll(args))
  },
  Campaign: {
    createdByRef: (campaign, args) => createdByRef(campaign.id, args),
    markingDefinitions: (campaign, args) => markingDefinitions(campaign.id, args),
    reports: (campaign, args) => reports(campaign.id, args),
    editContext: auth(campaign => fetchEditContext(campaign.id))
  },
  Mutation: {
    campaignEdit: auth((_, { id }, { user }) => ({
      delete: () => campaignDelete(id),
      fieldPatch: ({ input }) => campaignEditField(user, id, input),
      contextPatch: ({ input }) => campaignEditContext(user, id, input),
      relationAdd: ({ input }) => campaignAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        campaignDeleteRelation(user, id, relationId)
    })),
    campaignAdd: auth((_, { input }, { user }) => addCampaign(user, input))
  },
  Subscription: {
    campaign: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        campaignEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Campaign.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          campaignCleanContext(user, id);
        });
      })
    }
  }
};

export default campaignResolvers;
