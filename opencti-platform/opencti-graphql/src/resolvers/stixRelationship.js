import { includes } from 'ramda';
import {
  findStixRelationPaginated,
  findById,
  getSpecVersionOrDefault,
  schemaRelationsTypesMapping,
  stixRelationshipDelete,
  stixRelationshipsDistribution,
  stixRelationshipsMultiTimeSeries,
  stixRelationshipsNumber,
  stixRelationshipsTimeSeries
} from '../domain/stixRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, INPUT_CREATED_BY, } from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { stixLoadByIdStringify } from '../database/middleware';
import { loadThroughDenormalized } from './stix';
import { filterMembersWithUsersOrgs } from '../utils/access';

const stixRelationshipResolvers = {
  Query: {
    stixRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixRelationships: (_, args, context) => findStixRelationPaginated(context, context.user, args),
    stixRelationshipsTimeSeries: (_, args, context) => stixRelationshipsTimeSeries(context, context.user, args),
    stixRelationshipsMultiTimeSeries: (_, args, context) => stixRelationshipsMultiTimeSeries(context, context.user, args),
    stixRelationshipsDistribution: (_, args, context) => stixRelationshipsDistribution(context, context.user, args),
    stixRelationshipsNumber: (_, args, context) => stixRelationshipsNumber(context, context.user, args),
    schemaRelationsTypesMapping: () => schemaRelationsTypesMapping(),
  },
  StixRelationshipsOrdering: {},
  StixRelationship: {
    from: (rel, _, context) => {
      // If relation is in a draft, we want to force the context to also be in the same draft
      const idLoadArgs = { id: rel.fromId, type: rel.fromType };
      return (rel.from ? rel.from : context.batch.idsBatchLoader.load(idLoadArgs));
    },
    to: (rel, _, context) => {
      // If relation is in a draft, we want to force the context to also be in the same draft
      const idLoadArgs = { id: rel.toId, type: rel.toType };
      return (rel.to ? rel.to : context.batch.idsBatchLoader.load(idLoadArgs));
    },
    creators: async (rel, _, context) => {
      const creators = await context.batch.creatorsBatchLoader.load(rel.creator_id);
      if (!creators) {
        return [];
      }
      return filterMembersWithUsersOrgs(context, context.user, creators);
    },
    createdBy: (rel, _, context) => loadThroughDenormalized(context, context.user, rel, INPUT_CREATED_BY),
    toStix: (rel, args, context) => stixLoadByIdStringify(context, context.user, rel.id, args),
    objectMarking: (rel, _, context) => context.batch.markingsBatchLoader.load(rel, context, context.user),
    // eslint-disable-next-line
    __resolveType(obj) {
      if (STIX_REF_RELATIONSHIP_TYPES.some((type) => obj.parent_types.includes(type))) {
        return 'StixRefRelationship';
      }
      if (includes(ABSTRACT_STIX_CORE_RELATIONSHIP, obj.parent_types)) {
        return 'StixCoreRelationship';
      }
      if (STIX_SIGHTING_RELATIONSHIP === obj.entity_type) {
        return 'StixSightingRelationship';
      }
      /* v8 ignore next */
      return 'Unknown';
    },
    spec_version: getSpecVersionOrDefault
  },
  Mutation: {
    stixRelationshipEdit: (_, { id }, context) => ({
      delete: () => stixRelationshipDelete(context, context.user, id),
    }),
  },
};

export default stixRelationshipResolvers;
