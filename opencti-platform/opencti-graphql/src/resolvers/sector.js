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

const parentSectorsLoader = initBatchLoader(batchParentSectors);
const subSectorsLoader = initBatchLoader(batchSubSectors);
const isSubSectorLoader = initBatchLoader(batchIsSubSector);

const sectorResolvers = {
  Query: {
    sector: (_, { id }) => findById(id),
    sectors: (_, args) => findAll(args),
  },
  Sector: {
    parentSectors: (sector) => parentSectorsLoader.load(sector.id),
    subSectors: (sector) => subSectorsLoader.load(sector.id),
    isSubSector: (sector) => isSubSectorLoader.load(sector.id),
    targetedOrganizations: (sector) => targetedOrganizations(sector.id),
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
