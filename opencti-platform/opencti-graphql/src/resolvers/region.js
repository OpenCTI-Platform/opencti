import { addRegion, findAll, findById, parentRegions, subRegions, isSubRegion } from '../domain/region';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete,
} from '../domain/stixDomainEntity';
import { REL_INDEX_PREFIX } from '../database/elasticSearch';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../utils/idGenerator';

const regionResolvers = {
  Query: {
    region: (_, { id }) => findById(id),
    regions: (_, args) => findAll(args),
  },
  Region: {
    parentRegions: (region) => parentRegions(region.id),
    subRegions: (region) => subRegions(region.id),
    isSubRegion: (region, args) => isSubRegion(region.id, args),
  },
  RegionsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markingDefinitions: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labels: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
  },
  Mutation: {
    regionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(user, id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) => stixDomainEntityDeleteRelation(user, id, relationId),
    }),
    regionAdd: (_, { input }, { user }) => addRegion(user, input),
  },
};

export default regionResolvers;
