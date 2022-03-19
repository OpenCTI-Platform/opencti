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
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';

const countriesLoader = batchLoader(batchCountries);
const parentRegionsLoader = batchLoader(batchParentRegions);
const subRegionsLoader = batchLoader(batchSubRegions);
const isSubRegionLoader = batchLoader(batchIsSubRegion);

const regionResolvers = {
  Query: {
    region: (_, { id }, { user }) => findById(user, id),
    regions: (_, args, { user }) => findAll(user, args),
  },
  Region: {
    parentRegions: (region, _, { user }) => parentRegionsLoader.load(region.id, user),
    subRegions: (region, _, { user }) => subRegionsLoader.load(region.id, user),
    isSubRegion: (region, _, { user }) => isSubRegionLoader.load(region.id, user),
    countries: (region, _, { user }) => countriesLoader.load(region.id, user),
  },
  RegionsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
  },
  Mutation: {
    regionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    regionAdd: (_, { input }, { user }) => addRegion(user, input),
  },
};

export default regionResolvers;
