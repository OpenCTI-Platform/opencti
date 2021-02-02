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
import { REL_INDEX_PREFIX } from '../schema/general';
import { initBatchLoader } from '../database/middleware';

const countriesLoader = (user) => initBatchLoader(user, batchCountries);
const parentRegionsLoader = (user) => initBatchLoader(user, batchParentRegions);
const subRegionsLoader = (user) => initBatchLoader(user, batchSubRegions);
const isSubRegionLoader = (user) => initBatchLoader(user, batchIsSubRegion);

const regionResolvers = {
  Query: {
    region: (_, { id }, { user }) => findById(user, id),
    regions: (_, args, { user }) => findAll(user, args),
  },
  Region: {
    parentRegions: (region, _, { user }) => parentRegionsLoader(user).load(region.id),
    subRegions: (region, _, { user }) => subRegionsLoader(user).load(region.id),
    isSubRegion: (region, _, { user }) => isSubRegionLoader(user).load(region.id),
    countries: (region, _, { user }) => countriesLoader(user).load(region.id),
  },
  RegionsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    regionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    regionAdd: (_, { input }, { user }) => addRegion(user, input),
  },
};

export default regionResolvers;
