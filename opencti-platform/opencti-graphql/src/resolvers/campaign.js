import { addCampaign, campaignsTimeSeries, campaignsTimeSeriesByEntity, findCampaignPaginated, findById } from '../domain/campaign';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_CAMPAIGN } from '../schema/stixDomainObject';
import { findSecurityCoverageByCoveredId } from '../modules/securityCoverage/securityCoverage-domain';

const campaignResolvers = {
  Query: {
    campaign: (_, { id }, context) => findById(context, context.user, id),
    campaigns: (_, args, context) => findCampaignPaginated(context, context.user, args),
    campaignsTimeSeries: (_, args, context) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(context, context.user, args);
      }
      return campaignsTimeSeries(context, context.user, args);
    },
  },
  Campaign: {
    securityCoverage: (campaign, _, context) => findSecurityCoverageByCoveredId(context, context.user, campaign.id),
  },
  Mutation: {
    campaignEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_CAMPAIGN),
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
