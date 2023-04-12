import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { checkRelationshipRef, checkStixCoreRelationshipMapping } from '../database/stix';
import { FunctionalError } from '../config/errors';
import type { BasicObject } from '../generated/graphql';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';
import { isStixRefRelationship } from '../schema/stixRefRelationship';

type ConsistencyObject = Pick<BasicObject, 'entity_type'>;

export const checkRelationConsistency = async (
  context: AuthContext,
  user: AuthUser,
  relationshipType: string,
  from: ConsistencyObject,
  to: ConsistencyObject | ConsistencyObject[]
) => {
  const checkRelationConsistencyFn = async () => {
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
      } else if (isStixRefRelationship(relationshipType)) {
        checkRelationshipRef(fromType, toType, relationshipType);
      }
    });
  };
  return telemetry(context, user, 'CONSISTENCY relation', {
    [SemanticAttributes.DB_NAME]: 'search_engine',
    [SemanticAttributes.DB_OPERATION]: 'read',
  }, checkRelationConsistencyFn);
};
export const isRelationConsistent = async (
  context: AuthContext,
  user: AuthUser,
  relationshipType: string,
  from: ConsistencyObject,
  to: ConsistencyObject | ConsistencyObject[]
) => {
  try {
    await checkRelationConsistency(context, user, relationshipType, from, to);
    return true;
  } catch {
    return false;
  }
};
