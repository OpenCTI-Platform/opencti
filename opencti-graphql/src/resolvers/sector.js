import { addSector, sectorDelete, findAll, findById } from '../domain/sector';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityCleanContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';

import { fetchEditContext } from '../database/redis';

const sectorResolvers = {
  Query: {
    sector: (_, { id }) => findById(id),
    sectors: (_, args) => findAll(args)
  },
  Sector: {
    createdByRef: (sector, args) => createdByRef(sector.id, args),
    markingDefinitions: (sector, args) => markingDefinitions(sector.id, args),
    reports: (sector, args) => reports(sector.id, args),
    stixRelations: (campaign, args) => stixRelations(campaign.id, args),
    editContext: sector => fetchEditContext(sector.id)
  },
  Mutation: {
    sectorEdit: (_, { id }, { user }) => ({
      delete: () => sectorDelete(id),
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
