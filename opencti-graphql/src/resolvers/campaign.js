import {
  addCampaign,
  campaignDelete,
  findAll,
  findById
} from '../domain/campaign';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const campaignResolvers = {
  Query: {
    campaign: auth((_, { id }) => findById(id)),
    campaigns: auth((_, args) => findAll(args))
  },
  Campaign: {
    createdByRef: (campaign, args) => createdByRef(campaign.id, args),
    markingDefinitions: (campaign, args) =>
      markingDefinitions(campaign.id, args),
    reports: (campaign, args) => reports(campaign.id, args),
    stixRelations: (campaign, args) => stixRelations(campaign.id, args),
    editContext: auth(campaign => fetchEditContext(campaign.id))
  },
  Mutation: {
    campaignEdit: auth((_, { id }, { user }) => ({
      delete: () => campaignDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    campaignAdd: auth((_, { input }, { user }) => addCampaign(user, input))
  }
};

export default campaignResolvers;
