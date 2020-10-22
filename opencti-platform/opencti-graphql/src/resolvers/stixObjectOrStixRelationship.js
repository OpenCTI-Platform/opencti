import { includes } from 'ramda';
import { findById } from '../domain/stixObjectOrStixRelationship';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_META_RELATIONSHIP } from '../schema/general';
import { onlyStableStixIds } from '../database/stix';

const stixObjectOrStixRelationshipResolvers = {
  Query: {
    stixObjectOrStixRelationship: (_, { id }) => findById(id),
    stixCoreObjectOrStixCoreRelationship: (_, { id }) => findById(id),
  },
  StixObject: {
    x_opencti_stix_ids: (object) => onlyStableStixIds(object.x_opencti_stix_ids || []),
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
