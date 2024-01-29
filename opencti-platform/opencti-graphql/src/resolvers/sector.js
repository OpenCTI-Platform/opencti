import { addSector, childSectorsPaginated, findAll, findById, isSubSector, parentSectorsPaginated, targetedOrganizations } from '../domain/sector';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const sectorResolvers = {
  Query: {
    sector: (_, { id }, context) => findById(context, context.user, id),
    sectors: (_, args, context) => findAll(context, context.user, args),
  },
  Sector: {
    parentSectors: (sector, args, context) => parentSectorsPaginated(context, context.user, sector.id, args),
    subSectors: (sector, args, context) => childSectorsPaginated(context, context.user, sector.id, args),
    isSubSector: (sector, _, context) => isSubSector(context, context.user, sector.id),
    targetedOrganizations: (sector, _, context) => targetedOrganizations(context, context.user, sector.id),
  },
  Mutation: {
    sectorEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    sectorAdd: (_, { input }, context) => addSector(context, context.user, input),
  },
};

export default sectorResolvers;
