import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { deleteElementById } from '../../database/middleware';
import { fullRelationsList } from '../../database/middleware-loader';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import type { SecurityCoverageAddInput, StixCoreRelationshipAddInput } from '../../generated/graphql';
import { RELATION_HAS_COVERED } from '../../schema/stixCoreRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import type { BasicStoreRelation } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { findById, findSecurityCoverageByCoveredId, getSecurityCoverageResultIds, listSecurityCoverageResults, SECURITY_COVERAGE_SCOPE_RELATIONS } from './securityCoverage-domain';

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
 * Callers pass the entities whose link to the covered entity was just removed.
 * The ones still in scope through another link (a second uses relationship, an
 * object ref...) are kept, so calling it after a no-op removal is harmless.
 *
 * Runs as SYSTEM_USER so the cascade stays consistent whatever the rights of the
 * user performing the removal, and never throws: a failure here must not make the
 * removal itself fail.
 *
 * @param context To make the request to engine.
 * @param coveredEntityId Internal ID of the entity covered by a security coverage.
 * @param candidateIds Internal IDs of the entities that may have left the covered scope.
 */
export const removeHasCoveredForRemovedEntities = async (
  context: AuthContext,
  coveredEntityId: string,
  candidateIds: string[],
) => {
  if (candidateIds.length === 0) {
    return;
  }
  try {
    // 1. Resolve the security coverage of the entity, if any.
    const coverage = await findSecurityCoverageByCoveredId(context, SYSTEM_USER, coveredEntityId);
    if (!coverage) {
      return;
    }
    // 2. Its result-of refs are part of the refs every search loads by default, no reload needed.
    const resultIds = getSecurityCoverageResultIds(coverage);
    if (resultIds.length === 0) {
      return;
    }
    // 3. Keep the candidates still in scope through another link.
    // Mirrors securityCoverageStixBundle: an entity stays in the assessed scope while the covered
    // entity still reaches it through an object ref or a scope relationship. Built here, not at module
    // level, since securityCoverage-domain imports this module too.
    const scopeLinks = [RELATION_OBJECT, ...SECURITY_COVERAGE_SCOPE_RELATIONS];
    const remainingLinks = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, scopeLinks, {
      indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
      fromId: coveredEntityId,
      toId: candidateIds,
      baseData: true,
    });
    const stillInScopeIds = new Set(remainingLinks.map((relation) => relation.toId));
    const removedEntityIds = candidateIds.filter((id) => !stillInScopeIds.has(id));
    if (removedEntityIds.length === 0) {
      return;
    }
    // 4. Find the has-covered relationships between those results and the removed entities.
    // Inferred relationships are left to the rule engine.
    const relations = await fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, RELATION_HAS_COVERED, {
      indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
      fromId: resultIds,
      toId: removedEntityIds,
    });
    if (relations.length === 0) {
      return;
    }
    // 5. Delete them, the security coverage results themselves are kept.
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
      { cause: err, coveredEntityId, candidateIds },
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
