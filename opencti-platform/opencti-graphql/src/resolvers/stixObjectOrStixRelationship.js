import { includes } from 'ramda';
import { findById } from '../domain/stixObjectOrStixRelationship';
import {
  ABSTRACT_STIX_CORE_RELATIONSHIP,
  ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP,
  ABSTRACT_STIX_META_RELATIONSHIP,
} from '../schema/general';
import { onlyStableStixIds } from '../database/stix';
import { isInferredIndex } from '../database/utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { stixObjectOrStixRelationshipOptions } from '../schema/stixObjectOrStixRelationship';

const stixObjectOrStixRelationshipResolvers = {
  Query: {
    stixObjectOrStixRelationship: (_, { id }, { user }) => findById(user, id),
    stixCoreObjectOrStixCoreRelationship: (_, { id }, { user }) => findById(user, id),
  },
  StixObject: {
    is_inferred: (object) => isInferredIndex(object._index),
    x_opencti_stix_ids: (object) => onlyStableStixIds(object.x_opencti_stix_ids || []),
  },
  StixRelationship: {
    is_inferred: (object) => isInferredIndex(object._index),
    x_opencti_stix_ids: (object) => onlyStableStixIds(object.x_opencti_stix_ids || []),
  },
  StixObjectOrStixRelationshipsFilter: stixObjectOrStixRelationshipOptions.StixObjectOrStixRelationshipsFilter,
  StixObjectOrStixRelationship: {
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
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* istanbul ignore next */
      return 'Unknown';
    },
  },
};

export default stixObjectOrStixRelationshipResolvers;
