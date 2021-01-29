import {
  addSector,
  findAll,
  findById,
  batchIsSubSector,
  batchParentSectors,
  batchSubSectors,
  targetedOrganizations,
} from '../domain/sector';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { RELATION_CREATED_BY, RELATION_OBJECT_LABEL, RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { RELATION_PART_OF } from '../schema/stixCoreRelationship';
import { REL_INDEX_PREFIX } from '../schema/general';
import { initBatchLoader } from '../database/middleware';

const parentSectorsLoader = (user) => initBatchLoader(user, batchParentSectors);
const subSectorsLoader = (user) => initBatchLoader(user, batchSubSectors);
const isSubSectorLoader = (user) => initBatchLoader(user, batchIsSubSector);

const sectorResolvers = {
  Query: {
    sector: (_, { id }, { user }) => findById(user, id),
    sectors: (_, args, { user }) => findAll(user, args),
  },
  Sector: {
    parentSectors: (sector, _, { user }) => parentSectorsLoader(user).load(sector.id),
    subSectors: (sector, _, { user }) => subSectorsLoader(user).load(sector.id),
    isSubSector: (sector, _, { user }) => isSubSectorLoader(user).load(sector.id),
    targetedOrganizations: (sector, _, { user }) => targetedOrganizations(user, sector.id),
  },
  SectorsFilter: {
    createdBy: `${REL_INDEX_PREFIX}${RELATION_CREATED_BY}.internal_id`,
    markedBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_MARKING}.internal_id`,
    labelledBy: `${REL_INDEX_PREFIX}${RELATION_OBJECT_LABEL}.internal_id`,
    partOf: `${REL_INDEX_PREFIX}${RELATION_PART_OF}.internal_id`,
  },
  Mutation: {
    sectorEdit: (_, { id }, { user }) => ({
      delete: () => stixDomainObjectDelete(user, id),
      fieldPatch: ({ input }) => stixDomainObjectEditField(user, id, input),
      contextPatch: ({ input }) => stixDomainObjectEditContext(user, id, input),
      contextClean: () => stixDomainObjectCleanContext(user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) =>
        stixDomainObjectDeleteRelation(user, id, toId, relationshipType),
    }),
    sectorAdd: (_, { input }, { user }) => addSector(user, input),
  },
};

export default sectorResolvers;
