import { v4 as uuidv4 } from 'uuid';
import { type EntityOptions, fullRelationsList, loadEntityThroughRelationsPaginated, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../types/user';
import {
  type BasicStoreEntitySecurityCoverage,
  ENTITY_TYPE_SECURITY_COVERAGE,
  INPUT_COVERED,
  type OrganizationCoverageResult,
  RELATION_COVERED,
  type StoreEntitySecurityCoverage,
} from './securityCoverage-types';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { createEntity, deleteElementById, patchAttribute, storeLoadByIdsWithRefs, storeLoadByIdWithRefs } from '../../database/middleware';
import type { SecurityCoverageAddInput } from '../../generated/graphql';
import type { BasicStoreCommon, BasicStoreEntity, StoreObject, StoreRelation } from '../../types/store';
import { convertStoreToStix_2_1 } from '../../database/stix-2-1-converter';
import { STIX_SPEC_VERSION } from '../../database/stix';
import { RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import { stixRefsExtractor } from '../../schema/stixEmbeddedRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_VULNERABILITY,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } from '../case/case-incident/case-incident-types';
import { ENTITY_TYPE_CONTAINER_GROUPING } from '../grouping/grouping-types';
import { isBypassUser } from '../../utils/access';
import { addOrganizationRestriction } from '../../domain/stix';
import { ForbiddenAccess } from '../../config/errors';
import { getPlatformOrganizationId } from '../requestAccess/requestAccess-domain';

export const COVERED_ENTITIES_TYPE = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_CONTAINER_GROUPING,
  ENTITY_TYPE_CONTAINER_CASE_INCIDENT,
];

// region CRUD
export const findSecurityCoverageById = (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  return storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, SecurityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
};

export const pageSecurityCoverageConnections = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntitySecurityCoverage>) => {
  return pageEntitiesConnection<BasicStoreEntitySecurityCoverage>(context, user, [ENTITY_TYPE_SECURITY_COVERAGE], args);
};

export const findSecurityCoverageByCoveredId = async (context: AuthContext, user: AuthUser, coveredId: string) => {
  return loadEntityThroughRelationsPaginated<BasicStoreEntitySecurityCoverage>(context, user, coveredId, RELATION_COVERED, ENTITY_TYPE_SECURITY_COVERAGE, true);
};

export const addSecurityCoverage = async (context: AuthContext, user: AuthUser, securityCoverageInput: SecurityCoverageAddInput) => {
  const created = await createEntity(context, user, securityCoverageInput, ENTITY_TYPE_SECURITY_COVERAGE);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

// region Org-scoped coverage result management
export const filterCoverageInformationForUser = async (
  context: AuthContext,
  user: AuthUser,
  coverageInfo: OrganizationCoverageResult[] | undefined,
): Promise<OrganizationCoverageResult[]> => {
  if (!coverageInfo || coverageInfo.length === 0) {
    return [];
  }
  // BYPASS users see all
  if (isBypassUser(user)) {
    return coverageInfo;
  }
  const userOrgIds = (user.organizations ?? []).map((org: BasicStoreCommon) => org.internal_id);
  if (userOrgIds.length === 0) {
    return coverageInfo; // No org restriction, show all
  }
  // Include platform org results as baseline visible by all org users
  const platformOrgId = await getPlatformOrganizationId(context, user);
  const allowedOrgIds = new Set([...userOrgIds, ...(platformOrgId ? [platformOrgId] : [])]);
  return coverageInfo.filter((entry) => allowedOrgIds.has(entry.organization_id));
};

export const getMyCoverageResult = (
  context: AuthContext,
  user: AuthUser,
  coverageInfo: OrganizationCoverageResult[] | undefined,
): OrganizationCoverageResult | null => {
  if (!coverageInfo || coverageInfo.length === 0) {
    return null;
  }
  const userOrgIds = (user.organizations ?? []).map((org: BasicStoreCommon) => org.internal_id);
  if (userOrgIds.length === 0) {
    return coverageInfo[0] ?? null; // No org, return first
  }
  return coverageInfo.find((entry) => userOrgIds.includes(entry.organization_id)) ?? null;
};

export const securityCoveragePushResults = async (
  context: AuthContext,
  user: AuthUser,
  coverageId: string,
  organizationId: string,
  results: { coverage_name: string; coverage_score: number }[],
  autoEnrichment?: boolean,
) => {
  // Access control: user must belong to the target org or be a BYPASS user
  if (!isBypassUser(user)) {
    const userOrgIds = (user.organizations ?? []).map((org: BasicStoreCommon) => org.internal_id);
    if (!userOrgIds.includes(organizationId)) {
      throw ForbiddenAccess('You can only push coverage results for your own organization');
    }
  }
  const coverage = await storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, coverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  if (!coverage) {
    throw new Error(`SecurityCoverage ${coverageId} not found`);
  }
  // Load org to get its name
  const org = await storeLoadById<BasicStoreEntity>(context, user, organizationId, 'Identity');
  const orgName = org?.name ?? organizationId;

  const existingInfo: OrganizationCoverageResult[] = coverage.coverage_information ?? [];
  const existingIndex = existingInfo.findIndex((e) => e.organization_id === organizationId);

  const newEntry: OrganizationCoverageResult = {
    organization_id: organizationId,
    organization_name: orgName,
    last_result: new Date().toISOString(),
    auto_enrichment: autoEnrichment ?? false,
    results,
  };

  let updatedInfo: OrganizationCoverageResult[];
  if (existingIndex >= 0) {
    updatedInfo = [...existingInfo];
    updatedInfo[existingIndex] = newEntry;
  } else {
    updatedInfo = [...existingInfo, newEntry];
  }

  const patch = { coverage_information: updatedInfo };
  await patchAttribute(context, user, coverageId, ENTITY_TYPE_SECURITY_COVERAGE, patch);

  // Auto-manage objectOrganization for segregation
  try {
    await addOrganizationRestriction(context, user, coverageId, organizationId);
  } catch {
    // If already restricted or draft context, ignore
  }

  return storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, coverageId, ENTITY_TYPE_SECURITY_COVERAGE);
};

export const securityCoverageRemoveOrgResults = async (
  context: AuthContext,
  user: AuthUser,
  coverageId: string,
  organizationId: string,
) => {
  // Access control: user must belong to the target org or be a BYPASS user
  if (!isBypassUser(user)) {
    const userOrgIds = (user.organizations ?? []).map((org: BasicStoreCommon) => org.internal_id);
    if (!userOrgIds.includes(organizationId)) {
      throw ForbiddenAccess('You can only remove coverage results for your own organization');
    }
  }
  const coverage = await storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, coverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  if (!coverage) {
    throw new Error(`SecurityCoverage ${coverageId} not found`);
  }

  const existingInfo: OrganizationCoverageResult[] = coverage.coverage_information ?? [];
  const updatedInfo = existingInfo.filter((e) => e.organization_id !== organizationId);

  const patch = { coverage_information: updatedInfo };
  await patchAttribute(context, user, coverageId, ENTITY_TYPE_SECURITY_COVERAGE, patch);

  return storeLoadById<BasicStoreEntitySecurityCoverage>(context, user, coverageId, ENTITY_TYPE_SECURITY_COVERAGE);
};
// endregion

export const securityCoverageStixBundle = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  const objects = [];
  const SecurityCoverage = await storeLoadByIdWithRefs(context, user, SecurityCoverageId) as StoreEntitySecurityCoverage;
  const stixSecurityCoverage = convertStoreToStix_2_1(SecurityCoverage);
  objects.push(stixSecurityCoverage);
  const objectCoveredEntity = SecurityCoverage[INPUT_COVERED] as BasicStoreEntity;
  const assessment = await storeLoadByIdWithRefs(context, user, objectCoveredEntity.id) as StoreObject;
  const stixAssessment = convertStoreToStix_2_1(assessment);
  objects.push(stixAssessment);
  const stixAssessmentRefs = stixRefsExtractor(stixAssessment);
  const refElements = await storeLoadByIdsWithRefs(context, user, stixAssessmentRefs);
  for (let index = 0; index < refElements.length; index += 1) {
    const refElement = refElements[index];
    const stixRefElement = convertStoreToStix_2_1(refElement);
    objects.push(stixRefElement);
  }
  const targetIds = new Set<string>();
  const relationsCallback = async (relationships: StoreRelation[]) => {
    const relations = await storeLoadByIdsWithRefs<StoreRelation>(context, user, relationships.map((r: StoreRelation) => r.id));
    for (let index = 0; index < relations.length; index += 1) {
      const relation = relations[index];
      const stixRelation = convertStoreToStix_2_1(relation);
      objects.push(stixRelation);
      targetIds.add(relation.toId);
    }
  };
  await fullRelationsList(context, user, [RELATION_TARGETS, RELATION_USES], {
    fromId: objectCoveredEntity.id,
    toTypes: [ENTITY_TYPE_VULNERABILITY, ENTITY_TYPE_ATTACK_PATTERN],
    callback: relationsCallback,
  });
  if (targetIds.size > 0) {
    const targets = await storeLoadByIdsWithRefs(context, user, Array.from(targetIds));
    for (let index = 0; index < targets.length; index += 1) {
      const target = targets[index];
      const stixTarget = convertStoreToStix_2_1(target);
      objects.push(stixTarget);
    }
  }
  const StixBundle = { id: uuidv4(), spec_version: STIX_SPEC_VERSION, type: 'bundle', objects };
  return JSON.stringify(StixBundle);
};

export const objectCovered = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  return loadEntityThroughRelationsPaginated<T>(context, user, SecurityCoverageId, RELATION_COVERED, COVERED_ENTITIES_TYPE, false);
};

export const securityCoverageDelete = async (context: AuthContext, user: AuthUser, SecurityCoverageId: string) => {
  await deleteElementById(context, user, SecurityCoverageId, ENTITY_TYPE_SECURITY_COVERAGE);
  await notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].DELETE_TOPIC, SecurityCoverageId, user);
  return SecurityCoverageId;
};
// endregion
