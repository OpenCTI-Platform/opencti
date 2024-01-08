import { includes } from 'ramda';
import {
  batchCreatedBy,
  batchMarkingDefinitions,
  findAll,
  findById,
  getSpecVersionOrDefault,
  schemaRelationsTypesMapping,
  stixRelationshipDelete,
  stixRelationshipsDistribution,
  stixRelationshipsMultiTimeSeries,
  stixRelationshipsNumber
} from '../domain/stixRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, } from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { batchLoader, stixLoadByIdStringify, timeSeriesRelations } from '../database/middleware';
import { elBatchIds } from '../database/engine';
import { batchCreators } from '../domain/user';

const loadByIdLoader = batchLoader(elBatchIds);
const createdByLoader = batchLoader(batchCreatedBy);
const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const creatorsLoader = batchLoader(batchCreators);

const stixRelationshipResolvers = {
  Query: {
    stixRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixRelationships: (_, args, context) => findAll(context, context.user, args),
    stixRelationshipsTimeSeries: (_, args, context) => timeSeriesRelations(context, context.user, args),
    stixRelationshipsMultiTimeSeries: (_, args, context) => stixRelationshipsMultiTimeSeries(context, context.user, args),
    stixRelationshipsDistribution: (_, args, context) => stixRelationshipsDistribution(context, context.user, args),
    stixRelationshipsNumber: (_, args, context) => stixRelationshipsNumber(context, context.user, args),
    schemaRelationsTypesMapping: () => schemaRelationsTypesMapping(),
  },
  StixRelationshipsOrdering: {},
  StixRelationship: {
    from: (rel, _, context) => loadByIdLoader.load(rel.fromId, context, context.user),
    to: (rel, _, context) => loadByIdLoader.load(rel.toId, context, context.user),
    creators: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
    createdBy: (rel, _, context) => createdByLoader.load(rel.id, context, context.user),
    toStix: (rel, _, context) => stixLoadByIdStringify(context, context.user, rel.id),
    objectMarking: (rel, _, context) => markingDefinitionsLoader.load(rel.id, context, context.user),
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
