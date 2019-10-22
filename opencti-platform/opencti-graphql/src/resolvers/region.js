import { addRegion, findAll, findById } from '../domain/region';
import {
  createdByRef,
  markingDefinitions,
  tags,
  reports,
  exports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation,
  stixDomainEntityDelete
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';

const regionResolvers = {
  Query: {
    region: (_, { id }) => findById(id),
    regions: (_, args) => findAll(args)
  },
  Region: {
    createdByRef: region => createdByRef(region.id),
    markingDefinitions: (region, args) => markingDefinitions(region.id, args),
    tags: (region, args) => tags(region.id, args),
    reports: (region, args) => reports(region.id, args),
    exports: (region, args) => exports(region.id, args),
    stixRelations: (region, args) => stixRelations(region.id, args),
    editContext: region => fetchEditContext(region.id)
  },
  Mutation: {
    regionEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    regionAdd: (_, { input }, { user }) => addRegion(user, input)
  }
};

export default regionResolvers;
