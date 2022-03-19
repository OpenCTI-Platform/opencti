import { isStixCoreRelationship, STIX_CORE_RELATIONSHIPS } from './stixCoreRelationship';
import { isStixSightingRelationship, STIX_SIGHTING_RELATIONSHIP } from './stixSightingRelationship';
import {
  isStixCyberObservableRelationship,
  STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
} from './stixCyberObservableRelationship';
import { isStixMetaRelationship, STIX_META_RELATIONSHIPS } from './stixMetaRelationship';
import { isInternalRelationship } from './internalRelationship';

export const isStixRelationShipExceptMeta = (type) => isStixCoreRelationship(type) || isStixSightingRelationship(type) || isStixCyberObservableRelationship(type);

export const STIX_RELATIONSHIPS = [
  ...STIX_CORE_RELATIONSHIPS,
  STIX_SIGHTING_RELATIONSHIP,
  ...STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  ...STIX_META_RELATIONSHIPS,
];
export const isStixRelationship = (type) => isStixCoreRelationship(type)
  || isStixSightingRelationship(type)
  || isStixCyberObservableRelationship(type)
  || isStixMetaRelationship(type);

export const isBasicRelationship = (type) => isInternalRelationship(type) || isStixRelationship(type);
