import { isStixCoreRelationship } from './stixCoreRelationship';
import { isStixSightingRelationship } from './stixSightingRelationship';
import { isInternalRelationship } from './internalRelationship';
import { ABSTRACT_BASIC_RELATIONSHIP, ABSTRACT_STIX_RELATIONSHIP } from './general';
import { isStixRefRelationship } from './stixRefRelationship';
import type { StixRelation } from '../types/stix-2-1-sro';
import type { StixCoreObject } from '../types/stix-2-1-common';

export const isStixRelationshipExceptRef = (type: string) => isStixCoreRelationship(type) || isStixSightingRelationship(type);

export const isStixRelationship = (type: string) => isStixCoreRelationship(type)
  || isStixSightingRelationship(type)
  || isStixRefRelationship(type)
  || type === ABSTRACT_STIX_RELATIONSHIP;

export const isBasicRelationship = (type: string) => isInternalRelationship(type) || isStixRelationship(type) || type === ABSTRACT_BASIC_RELATIONSHIP;

export const isStixRelation = (sco: StixCoreObject): sco is StixRelation => {
  return (sco as StixRelation).relationship_type !== undefined;
};
