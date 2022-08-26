import { buildRefRelationKey } from './general';
import {
  RELATION_CREATED_BY, RELATION_EXTERNAL_REFERENCE, RELATION_OBJECT,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from './stixMetaRelationship';
import { RELATION_RELATED_TO } from './stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';

export const stixObjectOrStixRelationshipOptions = {
  StixObjectOrStixRelationshipsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    relatedTo: buildRefRelationKey(RELATION_RELATED_TO),
    objectContained: buildRefRelationKey(RELATION_OBJECT),
    containedBy: buildRefRelationKey(RELATION_OBJECT), // ASK SAM
    hasExternalReference: buildRefRelationKey(RELATION_EXTERNAL_REFERENCE),
    sightedBy: buildRefRelationKey(STIX_SIGHTING_RELATIONSHIP),
    hashes_MD5: 'hashes.MD5',
    hashes_SHA1: 'hashes.SHA-1',
    hashes_SHA256: 'hashes.SHA-256',
  },
};
