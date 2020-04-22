import { addRegion, findAll, findById, parentRegions, subRegions, isSubRegion } from '../domain/region';
import {
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete,
} from '../domain/stixDomainEntity';

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
  Mutation: {
    regionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
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
