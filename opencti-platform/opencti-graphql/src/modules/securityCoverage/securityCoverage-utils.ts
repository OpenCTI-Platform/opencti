import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import type { SecurityCoverageAddInput, StixCoreRelationshipAddInput } from '../../generated/graphql';
import { RELATION_HAS_COVERED } from '../../schema/stixCoreRelationship';
import type { AuthContext, AuthUser } from '../../types/user';
import { findById, listSecurityCoverageResults } from './securityCoverage-domain';

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
