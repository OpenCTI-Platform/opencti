import { addRegion, childRegionsPaginated, countriesPaginated, findAll, findById, parentRegionsPaginated } from '../domain/region';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const regionResolvers = {
  Query: {
    region: (_, { id }, context) => findById(context, context.user, id),
    regions: (_, args, context) => findAll(context, context.user, args),
  },
  Region: {
    parentRegions: (region, args, context) => parentRegionsPaginated(context, context.user, region.id, args),
    subRegions: (region, args, context) => childRegionsPaginated(context, context.user, region.id, args),
    countries: (region, args, context) => countriesPaginated(context, context.user, region.id, args),
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
