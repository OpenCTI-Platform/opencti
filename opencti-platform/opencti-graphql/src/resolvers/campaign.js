import { addCampaign, campaignsTimeSeries, campaignsTimeSeriesByEntity, findAll, findById } from '../domain/campaign';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';
import { UPDATE_OPERATION_REPLACE } from '../database/utils';

const campaignResolvers = {
  Query: {
    campaign: (_, { id }, { user }) => findById(user, id),
    campaigns: (_, args, { user }) => findAll(user, args),
    campaignsTimeSeries: (_, args, { user }) => {
      if (args.objectId && args.objectId.length > 0) {
        return campaignsTimeSeriesByEntity(user, args);
      }
      return campaignsTimeSeries(user, args);
    },
  },
  CampaignsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    campaignEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, operation = UPDATE_OPERATION_REPLACE }) =>
        stixDomainObjectEditField(user, id, input, { operation }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    campaignAdd: (_, { input }, { user }) => addCampaign(user, input),
  },
};

export default campaignResolvers;
