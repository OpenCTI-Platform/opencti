import { BUS_TOPICS, logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { deleteElementById, storeLoadByIdWithRefs } from '../../../database/middleware';
import { fullRelationsList, pageEntitiesConnection, storeLoadById, type EntityOptions } from '../../../database/middleware-loader';
import { notify } from '../../../database/redis';
import { addStixCoreRelationship } from '../../../domain/stixCoreRelationship';
import { type SecurityCoverageResultAddInput } from '../../../generated/graphql';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../schema/general';
import { RELATION_HAS_COVERED, RELATION_TARGETS, RELATION_USES } from '../../../schema/stixCoreRelationship';
import { isStixDomainObjectContainer } from '../../../schema/stixDomainObject';
import type { StoreEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ENTITY_TYPE_SECURITY_COVERAGE, RELATION_COVERED, type BasicStoreEntitySecurityCoverage } from '../securityCoverage-types';
import {
  ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  INPUT_RESULT_OF,
  type BasicStoreEntitySecurityCoverageResult,
  type StoreEntitySecurityCoverageResult,
} from './securityCoverageResult-types';
import { HAS_COVERED_TARGETS_TYPE, internalCreateSecurityCoverageResult } from './securityCoverageResult-utils';

/**
 * Find a security coverage results by its ID.
 *
 * @param context
 * @param user User making the request.
 * @param resultOfId ID of the security coverage result.
 * @returns Security coverage result.
 */
export const findById = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageId: string,
): Promise<BasicStoreEntitySecurityCoverageResult> => {
  return storeLoadById<BasicStoreEntitySecurityCoverageResult>(
    context,
    user,
    securityCoverageId,
    ENTITY_TYPE_SECURITY_COVERAGE_RESULT,
  );
};

/**
 * Find all security coverage results using pagination.
 *
 * @param context
 * @param user User making the request.
 * @param args Options to customize the query.
 * @returns Security coverage result.
 */
export const findSecurityCoverageResultPaginated = (
  context: AuthContext,
  user: AuthUser,
  args: EntityOptions<BasicStoreEntitySecurityCoverageResult>,
) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverageResult>(
    context,
    user,
    [ENTITY_TYPE_SECURITY_COVERAGE_RESULT],
    args,
  );
};

/**
 * Add a security coverage result.
 *
 * @param context
 * @param user User making the request.
 * @param  securityCoverageResultInput Data of the security coverage result.
 * @returns Created result.
 */
export const addSecurityCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResultInput: SecurityCoverageResultAddInput,
): Promise<BasicStoreEntitySecurityCoverageResult> => {
  const securityCoverage = await storeLoadById<BasicStoreEntitySecurityCoverage>(
    context,
    user,
    securityCoverageResultInput.resultOf,
    ENTITY_TYPE_SECURITY_COVERAGE,
  );
  if (!securityCoverage) {
    throw FunctionalError('Security coverage not found', { securityCoverageResultInput });
  }

  const input = {
    ...securityCoverageResultInput,
  };
  if (!securityCoverageResultInput.name) {
    input.name = `Result of ${securityCoverage.name}`;
  }
  const result = await internalCreateSecurityCoverageResult(context, user, input);
  return notify(
    BUS_TOPICS[ENTITY_TYPE_SECURITY_COVERAGE_RESULT].ADDED_TOPIC,
    result,
    user,
  );
};

/**
 * Delete a security coverage result by id.
 *
 * @param context
 * @param user User making the request.
 * @param id ID of the security coverage result.
 * @returns ID of deleted result.
 */
export const deleteSecurityCoverageResult = async (
  context: AuthContext,
  user: AuthUser,
  id: string,
) => {
  const deleted = await deleteElementById(context, user, id, ENTITY_TYPE_SECURITY_COVERAGE_RESULT);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, id, user);
  return deleted.id;
};

/**
 * /!\ This function could take quite a long time to execute, better to use it with background tasks.
 *
 * Creates a has-covered relationship between a security coverage result and each entities of
 * a covered entity.
 *
 * @param context
 * @param user User making the request.
 * @param securityCoverageResultId ID of the security coverage result to populate.
 */
export const addRelatedCoveredEntities = async (
  context: AuthContext,
  user: AuthUser,
  securityCoverageResultId: string,
) => {
  const securityCoverageResult = await storeLoadByIdWithRefs<StoreEntitySecurityCoverageResult>(context, user, securityCoverageResultId);
  if (!securityCoverageResult) {
    throw FunctionalError(`No security coverage result found for the id ${securityCoverageResultId}`);
  }

  const coveredId = securityCoverageResult[INPUT_RESULT_OF][RELATION_COVERED];
  const coveredEntity = await storeLoadByIdWithRefs<StoreEntity>(context, user, coveredId);
  if (!coveredEntity) {
    throw FunctionalError(`No covered entity found for the id ${coveredId}`);
  }

  let targets: string[] = [];
  if (isStixDomainObjectContainer(coveredEntity.entity_type)) {
    // In case of containers add entities from the ones contained.
    targets = (coveredEntity.objects ?? []).flatMap((o) => {
      if (!HAS_COVERED_TARGETS_TYPE.includes(o.entity_type)) return [];
      return o.id;
    });
  } else {
    // In case of non-containers add entities from targets and uses relationships.
    await fullRelationsList(context, user, [RELATION_TARGETS, RELATION_USES], {
      fromId: coveredEntity.id,
      toTypes: HAS_COVERED_TARGETS_TYPE,
      callback: async (relationships) => {
        targets.push(...relationships.map((r) => r.toId));
      },
    });
  }

  logApp.info(
    `[SECURITY-COVERAGE] addSecurityCoverage: Manual creation, ${targets.length} entities found for has-covered relationships`,
    { targets },
  );
  // Create all the has-covered relationships.
  return Promise.all(
    targets.map((target) => {
      return addStixCoreRelationship(context, user, {
        relationship_type: RELATION_HAS_COVERED,
        fromId: securityCoverageResultId,
        toId: target,
        coverage_information: [],
      });
    }),
  );
};
