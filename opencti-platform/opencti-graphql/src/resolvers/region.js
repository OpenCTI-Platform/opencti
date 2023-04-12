import {
  addRegion,
  findAll,
  findById,
  batchCountries,
  batchIsSubRegion,
  batchParentRegions,
  batchSubRegions,
} from '../domain/region';
import {
  stixDomainObjectEditContext,
  stixDomainObjectCleanContext,
  stixDomainObjectEditField,
  stixDomainObjectAddRelation,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';

const countriesLoader = batchLoader(batchCountries);
const parentRegionsLoader = batchLoader(batchParentRegions);
const subRegionsLoader = batchLoader(batchSubRegions);
const isSubRegionLoader = batchLoader(batchIsSubRegion);

const regionResolvers = {
  Query: {
    region: (_, { id }, context) => findById(context, context.user, id),
    regions: (_, args, context) => findAll(context, context.user, args),
  },
  Region: {
    parentRegions: (region, _, context) => parentRegionsLoader.load(region.id, context, context.user),
    subRegions: (region, _, context) => subRegionsLoader.load(region.id, context, context.user),
    isSubRegion: (region, _, context) => isSubRegionLoader.load(region.id, context, context.user),
    countries: (region, _, context) => countriesLoader.load(region.id, context, context.user),
  },
  RegionsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    regionEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    regionAdd: (_, { input }, context) => addRegion(context, context.user, input),
  },
};

export default regionResolvers;
