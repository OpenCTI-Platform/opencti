import { addRegion, batchCountries, batchIsSubRegion, batchParentRegions, batchSubRegions, findAll, findById } from '../domain/region';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
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
