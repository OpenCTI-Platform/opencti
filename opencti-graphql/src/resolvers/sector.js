import { addSector, sectorDelete, findAll, findById } from '../domain/sector';
import {
  createdByRef,
  markingDefinitions,
  reports,
  stixRelations,
  stixDomainEntityEditContext,
  stixDomainEntityEditField,
  stixDomainEntityAddRelation,
  stixDomainEntityDeleteRelation
} from '../domain/stixDomainEntity';
import { fetchEditContext } from '../database/redis';
import { auth } from './wrapper';

const sectorResolvers = {
  Query: {
    sector: auth((_, { id }) => findById(id)),
    sectors: auth((_, args) => findAll(args))
  },
  Sector: {
    createdByRef: (sector, args) => createdByRef(sector.id, args),
    markingDefinitions: (sector, args) => markingDefinitions(sector.id, args),
    reports: (sector, args) => reports(sector.id, args),
    stixRelations: (campaign, args) => stixRelations(campaign.id, args),
    editContext: auth(sector => fetchEditContext(sector.id))
  },
  Mutation: {
    sectorEdit: auth((_, { id }, { user }) => ({
      delete: () => sectorDelete(id),
      fieldPatch: ({ input }) => stixDomainEntityEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainEntityEditContext(user, id, input),
      relationAdd: ({ input }) => stixDomainEntityAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixDomainEntityDeleteRelation(user, id, relationId)
    })),
    sectorAdd: auth((_, { input }, { user }) => addSector(user, input))
  }
};

export default sectorResolvers;
