import {
  addCampaign,
  campaignDelete,
  findAll,
  search,
  findById,
  campaignsTimeSeries,
  campaignsTimeSeriesByEntity
} from '../domain/campaign';
import {
  createdByRef,
  markingDefinitions,
  reports,
  exports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const campaignResolvers = {
  Query: {
    campaign: (_, { id }) => findById(id),
    campaigns: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      return findAll(args);
    },
    campaignsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(args);
      }
      return campaignsTimeSeries(args);
    }
  },
  Campaign: {
    createdByRef: (campaign, args) => createdByRef(campaign.id, args),
    markingDefinitions: (campaign, args) =>
      markingDefinitions(campaign.id, args),
    reports: (campaign, args) => reports(campaign.id, args),
    exports: (campaign, args) => exports(campaign.id, args),
    stixRelations: (campaign, args) => stixRelations(campaign.id, args),
    editContext: campaign => fetchEditContext(campaign.id)
  },
  Mutation: {
    campaignEdit: (_, { id }, { user }) => ({
      delete: () => campaignDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    campaignAdd: (_, { input }, { user }) => addCampaign(user, input)
  }
};

export default campaignResolvers;
