import { addCampaign, campaignsTimeSeries, campaignsTimeSeriesByEntity, findAll, findById } from '../domain/campaign';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';

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
  CampaignsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
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
