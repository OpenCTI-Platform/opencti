import { addCampaign, campaignsTimeSeries, campaignsTimeSeriesByEntity, findAll, findById } from '../domain/campaign';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField
} from '../domain/stixDomainEntity';

const campaignResolvers = {
  Query: {
    campaign: (_, { id }) => findById(id),
    campaigns: (_, args) => findAll(args),
    campaignsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(args);
      }
      return campaignsTimeSeries(args);
    }
  },
  CampaignsFilter: {
    tags: 'tagged.internal_id_key'
  },
  Mutation: {
    campaignEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    campaignAdd: (_, { input }, { user }) => addCampaign(user, input)
  }
};

export default campaignResolvers;
