import { addCampaign, campaignsTimeSeries, campaignsTimeSeriesByEntity, findAll, findById } from '../domain/campaign';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const campaignResolvers = {
  Query: {
    campaign: (_, { id }, context) => findById(context, context.user, id),
    campaigns: (_, args, context) => findAll(context, context.user, args),
    campaignsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(context, context.user, args);
      }
      return campaignsTimeSeries(context, context.user, args);
    },
  },
  Mutation: {
    campaignEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    campaignAdd: (_, { input }, context) => addCampaign(context, context.user, input),
  },
};

export default campaignResolvers;
