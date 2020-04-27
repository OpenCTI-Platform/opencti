import { addCampaign, campaignsTimeSeries, campaignsTimeSeriesByEntity, findAll, findById } from '../domain/campaign';
import {
  stixDomainEntityAddRelation,
  stixDomainEntityCleanContext,
  stixDomainEntityDelete,
  stixDomainEntityDeleteRelation,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';

const campaignResolvers = {
  Query: {
    campaign: (_, { id }) => findById(id),
    campaigns: (_, args) => findAll(args),
    campaignsTimeSeries: (_, args) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(args);
      }
      return campaignsTimeSeries(args);
    },
  },
  CampaignsOrdering: {
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.definition`,
    tags: `${REL_INDEX_PREFIX}tagged.value`,
  },
  CampaignsFilter: {
    createdBy: `${REL_INDEX_PREFIX}created_by_ref.internal_id_key`,
    markingDefinitions: `${REL_INDEX_PREFIX}object_marking_refs.internal_id_key`,
    tags: `${REL_INDEX_PREFIX}tagged.internal_id_key`,
  },
  Mutation: {
    campaignEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    campaignAdd: (_, { input }, { user }) => addCampaign(user, input),
  },
};

export default campaignResolvers;
