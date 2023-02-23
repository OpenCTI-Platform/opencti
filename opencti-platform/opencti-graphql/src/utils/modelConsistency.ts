import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import {
  checkMetaRelationship,
  checkStixCoreRelationshipMapping,
  checkStixCyberObservableRelationshipMapping
} from '../database/stix';
import { FunctionalError } from '../config/errors';
import { isStixCyberObservableRelationship } from '../schema/stixCyberObservableRelationship';
import type { BasicObject } from '../generated/graphql';
import { isStixMetaRelationship } from '../schema/stixMetaRelationship';

type ConsistencyObject = Pick<BasicObject, 'entity_type'>;

export const checkRelationConsistency = (relationshipType: string, from: ConsistencyObject, to: ConsistencyObject | ConsistencyObject[]) => {
  // 01 - check type consistency
  const fromType = from.entity_type;
  const arrayTo = Array.isArray(to) ? to : [to];
  arrayTo.forEach(({ entity_type: toType }) => {
    // Check if StixCoreRelationship is allowed
    if (isStixCoreRelationship(relationshipType)) {
      if (!checkStixCoreRelationshipMapping(fromType, toType, relationshipType)) {
        throw FunctionalError(
          `The relationship type ${relationshipType} is not allowed between ${fromType} and ${toType}`
        );
      }
    } else if (isStixCyberObservableRelationship(relationshipType)) {
      // Check if StixCyberObservableRelationship is allowed
      if (!checkStixCyberObservableRelationshipMapping(fromType, toType, relationshipType)) {
        throw FunctionalError(
          `The relationship type ${relationshipType} is not allowed between ${fromType} and ${toType}`
        );
      }
    } else if (isStixMetaRelationship(relationshipType)) {
      checkMetaRelationship(fromType, toType, relationshipType);
    }
  });
};
export const isRelationConsistent = (relationshipType: string, from: ConsistencyObject, to: ConsistencyObject | ConsistencyObject[]) => {
  try {
    checkRelationConsistency(relationshipType, from, to);
    return true;
  } catch {
    return false;
  }
};
