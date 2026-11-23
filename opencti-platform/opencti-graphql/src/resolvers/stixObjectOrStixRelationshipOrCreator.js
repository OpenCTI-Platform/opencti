import { includes } from 'ramda';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../schema/general';
import { onlyStableStixIds } from '../database/stix';
import { isInferredIndex } from '../database/utils';
import { STIX_SIGHTING_RELATIONSHIP } from '../schema/stixSightingRelationship';
import { ENTITY_TYPE_USER } from '../schema/internalObject';
import { STIX_REF_RELATIONSHIP_TYPES } from '../schema/stixRefRelationship';
import { extractRepresentative } from '../database/entity-representative';

const RESTRICTED_NAME = 'Restricted';

// A relationship denormalizes the names of its endpoints (fromName / toName) without their access rights.
// Same check as the from / to resolvers: an endpoint the user cannot load is not accessible.
const isEndpointAccessible = async (rel, side, context) => {
  if (rel[side]) {
    return true;
  }
  const id = rel[`${side}Id`];
  if (!id) {
    return true; // nothing to check (relationship not read from the database), keep the stored name
  }
  return !!(await context.batch.idsBatchLoader.load({ id, type: rel[`${side}Type`] }));
};

const stixObjectOrStixRelationshipOrCreatorResolvers = {
  StixObject: {
    is_inferred: (object) => isInferredIndex(object._index),
    x_opencti_stix_ids: (object) => onlyStableStixIds(object.x_opencti_stix_ids || []),
    representative: (object) => extractRepresentative(object),
  },
  StixRelationship: {
    is_inferred: (object) => isInferredIndex(object._index),
    x_opencti_stix_ids: (object) => onlyStableStixIds(object.x_opencti_stix_ids || []),
    representative: async (rel, _, context) => {
      // the representative can already be given (internals set it to "Restricted")
      if (rel.representative) {
        return rel.representative;
      }
      const [isFromAccessible, isToAccessible] = await Promise.all([
        isEndpointAccessible(rel, 'from', context),
        isEndpointAccessible(rel, 'to', context),
      ]);
      return extractRepresentative({
        ...rel,
        fromName: isFromAccessible ? rel.fromName : RESTRICTED_NAME,
        toName: isToAccessible ? rel.toName : RESTRICTED_NAME,
      });
    },
  },
  Creator: {
    representative: (object) => extractRepresentative(object),
  },
  StixObjectOrStixRelationshipOrCreator: {
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
      if (obj.entity_type === ENTITY_TYPE_USER) {
        return 'Creator';
      }
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-|_)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      /* v8 ignore next */
      return 'Unknown';
    },
  },
};

export default stixObjectOrStixRelationshipOrCreatorResolvers;
