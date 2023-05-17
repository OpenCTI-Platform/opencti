import { includes } from 'ramda';
import { findAll, findById, getSpecVersionOrDefault, stixRelationshipDelete } from '../domain/stixRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, } from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';

const stixRelationshipResolvers = {
  Query: {
    stixRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixRelationships: (_, args, context) => findAll(context, context.user, args),
  },
  StixRelationship: {
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
      /* istanbul ignore next */
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
