import { addSector, findAll, findById, subsectors } from '../domain/sector';
import {
  createdByRef,
  markingDefinitions,
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

const sectorResolvers = {
  Query: {
    sector: (_, { id }) => findById(id),
    sectors: (_, args) => findAll(args)
  },
  Sector: {
    subsectors: (sector, args) => subsectors(sector.id, args),
    createdByRef: sector => createdByRef(sector.id),
    markingDefinitions: (sector, args) => markingDefinitions(sector.id, args),
    reports: (sector, args) => reports(sector.id, args),
    exports: (sector, args) => exports(sector.id, args),
    stixRelations: (campaign, args) => stixRelations(campaign.id, args),
    editContext: sector => fetchEditContext(sector.id)
  },
  Mutation: {
    sectorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainEntityDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      contextClean: () => stixDomainEntityCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    }),
    sectorAdd: (_, { input }, { user }) => addSector(user, input)
  }
};

export default sectorResolvers;
