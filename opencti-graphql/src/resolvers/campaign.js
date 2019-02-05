import {
  addCampaign,
  campaignDelete,
  findAll,
  findById,
  campaignsTimeSeries,
  campaignsTimeSeriesByEntity
} from '../domain/campaign';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const campaignResolvers = {
  Query: {
    campaign: auth((_, { id }) => findById(id)),
    campaigns: auth((_, args) => findAll(args)),
    campaignsTimeSeries: auth((_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(args);
      }
      return campaignsTimeSeries(args);
    })
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
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    campaignAdd: auth((_, { input }, { user }) => addCampaign(user, input))
  }
};

export default campaignResolvers;
