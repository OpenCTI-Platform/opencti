import { includes } from 'ramda';
import { findById } from '../domain/stixObjectOrStixRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_META_RELATIONSHIP } from '../utils/idGenerator';

const stixObjectOrStixRelationshipResolvers = {
  Query: {
    stixObjectOrStixRelationship: (_, { id }) => findById(id),
  },
  StixObjectOrStixRelationship: {
    // eslint-disable-next-line
    __resolveType(obj) {
      if (includes(ABSTRACT_STIX_META_RELATIONSHIP, obj.parent_types)) {
        return 'StixMetaRelationship';
      }
      if (includes(ABSTRACT_STIX_CORE_RELATIONSHIP, obj.parent_types)) {
        return 'StixCoreRelationship';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
  },
};

export default stixObjectOrStixRelationshipResolvers;
