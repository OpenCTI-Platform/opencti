import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { deleteElementById } from '../../database/middleware';
import { fullRelationsList } from '../../database/middleware-loader';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import type { SecurityCoverageAddInput, StixCoreRelationshipAddInput } from '../../generated/graphql';
import { RELATION_HAS_COVERED } from '../../schema/stixCoreRelationship';
import type { BasicStoreRelation } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { findById, findSecurityCoverageByCoveredId, getSecurityCoverageResultIds, listSecurityCoverageResults } from './securityCoverage-domain';

/**
 * Checks if the relationship fromId should be changed.
 * If the rel is 'has-covered' with a fromId of a securityCoverage,
 * Then changes fromId to the id of the associated securityCoverageResult.
 *
 * @param relInput Relationship input to check.
 * @returns True if the fromId of the input should be changed.
 */
export const shouldHandleHasCoveredRel = (relInput: StixCoreRelationshipAddInput): boolean => {
  return relInput.relationship_type === RELATION_HAS_COVERED
    && relInput.fromId.startsWith('security-coverage--');
};

/**
 * Replaces securityCoverage fromId to ID of associated securityCoverageResult.
 *
 * @param context To make the request to engine.
 * @param user To make the request to engine.
 * @param relInput Relationship input to manipulate.
 * @returns Transformed input.
 */
export const transformHasCoveredFromId = async (
  context: AuthContext,
  user: AuthUser,
  relInput: StixCoreRelationshipAddInput,
) => {
  // We remove the stix_id send by OpenAEV because it cannot compute the right one.
  // It misses the knowledge of the SCR that we are computing below.
  delete relInput.stix_id;

  const securityCoverage = await findById(context, user, relInput.fromId);
  const securityCoverageResults = await listSecurityCoverageResults(context, user, securityCoverage);
  const matchingSCR = relInput.external_uri
    ? securityCoverageResults.filter((scr) => scr.external_uri === relInput.external_uri)
    // Retro compatibility : only for old OEAV version without external_uri
    : securityCoverageResults;

  if (matchingSCR.length !== 1) {
    logApp.error(
      `[SECURITY-COVERAGE-RESULT] Invalid number of SCR found: ${relInput.external_uri}`,
      {
        relInput,
        matchingSCRStandardIds: matchingSCR.map((scr) => scr.standard_id),
      },
    );
    throw FunctionalError('Cannot find SecurityCoverageResult for this has-covered relationship');
  }
  return {
    ...relInput,
    fromId: matchingSCR[0].standard_id,
  };
};

/**
 * Deletes the has-covered relationships pointing at entities that are no longer
 * part of the scope covered by a security coverage.
 *
 * Runs as SYSTEM_USER so the cascade stays consistent whatever the rights of the
 * user performing the removal, and never throws: a failure here must not make the
 * removal itself fail.
 *
 * @param context To make the request to engine.
 * @param coveredEntityId Internal ID of the entity covered by a security coverage.
 * @param removedEntityIds Internal IDs of the entities removed from the covered scope.
 */
export const removeHasCoveredForRemovedEntities = async (
  context: AuthContext,
  coveredEntityId: string,
  removedEntityIds: string[],
) => {
  if (removedEntityIds.length === 0) {
    return;
  }
  try {
    // 1. Resolve the security coverage of the entity, if any.
    const coverage = await findSecurityCoverageByCoveredId(context, SYSTEM_USER, coveredEntityId);
    if (!coverage) {
      return;
    }
    // 2. Reload it to get the denormalized result-of refs.
    const securityCoverage = await findById(context, SYSTEM_USER, coverage.id);
    const resultIds = getSecurityCoverageResultIds(securityCoverage);
    if (resultIds.length === 0) {
      return;
    }
    // 3. Find the has-covered relationships between those results and the removed entities.
    // Inferred relationships are left to the rule engine.
    const relations = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, RELATION_HAS_COVERED, {
      indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
      fromId: resultIds,
      toId: removedEntityIds,
    });
    if (relations.length === 0) {
      return;
    }
    // 4. Delete them, the security coverage results themselves are kept.
    for (const relation of relations) {
      await deleteElementById(context, SYSTEM_USER, relation.internal_id, relation.entity_type);
    }
    logApp.info(
      `[SECURITY-COVERAGE][${coverage.id}] has-covered relationships deleted after entity removal`,
      { coveredEntityId, removedEntityIds, deletedIds: relations.map((relation) => relation.standard_id) },
    );
  } catch (err) {
    logApp.error(
      '[SECURITY-COVERAGE] Cannot clean up has-covered relationships after entity removal',
      { cause: err, coveredEntityId, removedEntityIds },
    );
  }
};

/**
 * Helper function to split the input of security coverage creation.
 *
 * @param input Input received to create a new security coverage.
 * @returns The input splitted into the part for SC and the part for SCR.
 */
export const splitSecurityCoverageInput = (input: SecurityCoverageAddInput) => {
  const {
    coverage_information,
    coverage_last_result,
    coverage_valid_from,
    coverage_valid_to,
    external_uri,
    tenant_name,
    tenant_id,
    add_related_entities,
    ...securityCoverageInput
  } = input;

  const {
    confidence,
    created,
    createdBy,
    fileMarkings,
    filesMarkings,
    modified,
    objectLabel,
    objectMarking,
    x_opencti_modified_at,
  } = securityCoverageInput;
  const securityCoverageResultInput = {
    name: tenant_name || external_uri || tenant_id,
    coverage_information,
    coverage_last_result,
    coverage_valid_from,
    coverage_valid_to,
    external_uri,
    confidence,
    created,
    createdBy,
    fileMarkings,
    filesMarkings,
    modified,
    objectLabel,
    objectMarking,
    x_opencti_modified_at,
  };

  // We should create a SecurityCoverageResult associated to the SecurityCoverage in two cases:
  // 1. We explicitly ask for it with add_related_entities (manual creation),
  // 2. The input contains result data, meaning the input came from OpenAEV.
  const shouldCreateResult = !!add_related_entities
    || !!external_uri
    || (coverage_information ?? []).length > 0;

  return {
    securityCoverageInput,
    securityCoverageResultInput,
    shouldCreateResult,
    add_related_entities,
  };
};
