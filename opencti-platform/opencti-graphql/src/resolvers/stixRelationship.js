import { includes } from 'ramda';
import { findById, findAll, stixRelationshipDelete } from '../domain/stixRelationship';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
} from '../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';

const stixRelationshipResolvers = {
  Query: {
    stixRelationship: (_, { id }, { user }) => findById(user, id),
    stixRelationships: (_, args, { user }) => findAll(user, args),
  },
  StixRelationship: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (includes(ABSTRACT_STIX_META_RELATIONSHIP, obj.parent_types)) {
        return 'StixMetaRelationship';
      }
      if (includes(ABSTRACT_STIX_CORE_RELATIONSHIP, obj.parent_types)) {
        return 'StixCoreRelationship';
      }
      if (STIX_SIGHTING_RELATIONSHIP === obj.entity_type) {
        return 'StixSightingRelationship';
      }
      if (includes(ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP, obj.parent_types)) {
        return 'StixCyberObservableRelationship';
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
  },
  Mutation: {
    stixRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixRelationshipDelete(user, id),
    }),
  },
};

export default stixRelationshipResolvers;
