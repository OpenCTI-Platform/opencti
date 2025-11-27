import { SEMATTRS_DB_NAME, SEMATTRS_DB_OPERATION } from '@opentelemetry/semantic-conventions';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { checkRelationshipRef, checkStixCoreRelationshipMapping } from '../database/stix';
import { FunctionalError } from '../config/errors';
import type { BasicObject } from '../generated/graphql';
import { telemetry } from '../config/tracing';
import type { AuthContext, AuthUser } from '../types/user';
import { isStixRefRelationship } from '../schema/stixRefRelationship';
import { RELATION_HAS_CAPABILITY_IN_DRAFT } from '../schema/internalRelationship';
import { CAPABILITIES_IN_DRAFT_NAMES } from './access';

type ConsistencyObject = Pick<BasicObject, 'entity_type'> & { name: string };

const isCapabilityDraftRelationAllowed = (relationshipType: string, toName: string): boolean => {
  const isCapabilitiesInDraftRelation = relationshipType === RELATION_HAS_CAPABILITY_IN_DRAFT;
  if (isCapabilitiesInDraftRelation) {
    return CAPABILITIES_IN_DRAFT_NAMES.includes(toName);
  }
  return true;
};

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
    arrayTo.forEach(({ entity_type: toType, name }) => {
      // Check if StixCoreRelationship is allowed
      isCapabilityDraftRelationAllowed(relationshipType, name);
      if (isStixCoreRelationship(relationshipType)) {
        if (!checkStixCoreRelationshipMapping(fromType, toType, relationshipType)) {
          throw FunctionalError(
            `The relationship type ${relationshipType} is not allowed between ${fromType} and ${toType}`
          );
        }
      } else if (isStixRefRelationship(relationshipType)) {
        checkRelationshipRef(fromType, toType, relationshipType);
      } else if (!isCapabilityDraftRelationAllowed(relationshipType, name)) {
        // Only allowed had-capability-in-draft with defined CAPABILITIES_IN_DRAFT_NAMES
        throw FunctionalError(`The relationship type ${relationshipType} is not allowed with the ${toType} ${name}`);
      }
    });
  };
  return telemetry(context, user, 'CONSISTENCY relation', {
    [SEMATTRS_DB_NAME]: 'search_engine',
    [SEMATTRS_DB_OPERATION]: 'read',
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
