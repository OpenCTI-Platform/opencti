import {
  DEPLOYMENT_STATUS_PENDING,
  DEPLOYMENT_STATUSES,
  type DeployedOnAttributes,
  type DeploymentStatus,
  VALIDATION_STATUS_NOT_REQUESTED,
  VALIDATION_STATUSES,
  type ValidationStatus,
} from './indicatorDeployment-types';
import { v5 as uuidv5 } from 'uuid';
import { FunctionalError } from '../../config/errors';
import { OPENCTI_NAMESPACE } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';

export const isDeploymentStatus = (value: unknown): value is DeploymentStatus => {
  return typeof value === 'string' && (DEPLOYMENT_STATUSES as readonly string[]).includes(value);
};

export const isValidationStatus = (value: unknown): value is ValidationStatus => {
  return typeof value === 'string' && (VALIDATION_STATUSES as readonly string[]).includes(value);
};

type MarkedElement = { [RELATION_OBJECT_MARKING]?: string[] | null };
type RestrictedElement = MarkedElement & { [RELATION_GRANTED_TO]?: string[] | null; [RELATION_CREATED_BY]?: string | null; restricted_members?: unknown[] | null };

/**
 * Markings of a relationship generated for an (indicator, security platform) pair: the deployment, its hits sighting
 * and the validation result sightings. Access to a relationship is checked on its own markings, so it carries those of
 * both ends: a reader of the indicator never sees the deployments, hits or results of a more restricted platform.
 */
export const pairMarkings = (indicator: MarkedElement, platform: MarkedElement): string[] => {
  return [...new Set([...(indicator[RELATION_OBJECT_MARKING] ?? []), ...(platform[RELATION_OBJECT_MARKING] ?? [])])];
};

type SharedElement = { [RELATION_GRANTED_TO]?: string[] | null };

/**
 * Organizations a relationship generated for an (indicator, security platform) pair is shared with: those both ends are
 * shared with, never the organizations of the reporting account. A user outside the platform organization reads an
 * element only through an organization it is shared with, so a reader of one end never reads the deployment, hits or
 * results of a pair whose other end is not shared with its organization.
 */
export const pairOrganizations = (indicator: SharedElement, platform: SharedElement): string[] => {
  const platformOrganizations = platform[RELATION_GRANTED_TO] ?? [];
  return [...new Set((indicator[RELATION_GRANTED_TO] ?? []).filter((organization) => platformOrganizations.includes(organization)))];
};

type MemberRestrictedElement = { restricted_members?: unknown[] | null };

/**
 * The relationships generated for a pair (deployment, hits and validation result sightings) and the validation requests
 * carry the markings and organizations of their ends, never authorized members: no single member list stands for the
 * readers of several ends. Indicators and security platforms do not support authorized members, so an end restricted to
 * some is refused rather than projected without them.
 */
export const checkEndsWithoutAuthorizedMembers = (ends: MemberRestrictedElement[]) => {
  if (ends.some((end) => (end.restricted_members ?? []).length > 0)) {
    throw FunctionalError('Deployments, hits, validation results and validation requests cannot involve an element restricted to authorized members');
  }
};

/**
 * Whether the account reporting for a pair reads a pair relationship shared with these organizations: it maintains the
 * relationship, so it must find it again on its next report. Organizations only restrict reads when a platform
 * organization is set, and never for the accounts inside it (service accounts included).
 */
export const isPairReadableByReporter = (organizations: string[], reporter: { insidePlatformOrganization: boolean; organizationIds: string[] }) => {
  return reporter.insidePlatformOrganization || organizations.some((organization) => reporter.organizationIds.includes(organization));
};

/**
 * Whether every reader of the indicator can read the deployment. The counters stored on the indicator only count such
 * deployments, so they never reveal the deployments, hits or results a reader of the indicator cannot read:
 * - markings: the deployment carries no marking the indicator does not carry;
 * - organizations: the deployment is shared with every organization the indicator is shared with (an indicator shared
 *   with no organization is only read by the platform organization, which reads every deployment);
 * - authorized members: neither has any, since authorized members of the indicator read it whatever their
 *   organization and nothing proves they can read the deployment (such deployments are left out of the counters).
 * The same holds for the security platform of the deployment, whose own restrictions are checked as well: a deployment
 * is shared with the organizations both ends are shared with, which can be fewer than those of the indicator.
 * Organizations only restrict reads when a platform organization is set; then the users of an individual read what
 * this individual created, so an indicator created by an individual only counts what the same individual created.
 */
export const isReadableWithIndicator = (
  deployment: RestrictedElement,
  indicator: RestrictedElement,
  platform?: RestrictedElement,
  organizationSharing: { enforced: boolean; individualIds: Set<string> } = { enforced: false, individualIds: new Set() },
  markingRanks: Map<string, { type: string; order: number }> = new Map(),
) => {
  if ((indicator.restricted_members ?? []).length > 0) {
    return false;
  }
  const indicatorMarkings = indicator[RELATION_OBJECT_MARKING] ?? [];
  const indicatorOrganizations = indicator[RELATION_GRANTED_TO] ?? [];
  const indicatorCreator = indicator[RELATION_CREATED_BY];
  // A reader cleared for a marking is cleared for the lower ones of the same type (TLP:RED covers TLP:GREEN)
  const isCovered = (marking: string) => indicatorMarkings.includes(marking) || indicatorMarkings.some((indicatorMarking) => {
    const covering = markingRanks.get(indicatorMarking);
    const covered = markingRanks.get(marking);
    return !!covering && !!covered && covering.type === covered.type && covering.order >= covered.order;
  });
  const readableByIndicatorReaders = (element: RestrictedElement) => {
    if (!(element[RELATION_OBJECT_MARKING] ?? []).every(isCovered)) return false;
    if ((element.restricted_members ?? []).length > 0) return false;
    if (!organizationSharing.enforced) return true;
    const elementOrganizations = element[RELATION_GRANTED_TO] ?? [];
    if (!indicatorOrganizations.every((organization) => elementOrganizations.includes(organization))) return false;
    return !indicatorCreator || !organizationSharing.individualIds.has(indicatorCreator) || element[RELATION_CREATED_BY] === indicatorCreator;
  };
  return readableByIndicatorReaders(deployment) && (!platform || readableByIndicatorReaders(platform));
};

const OPTIONAL_DEPLOYED_ON_KEYS = [
  'external_id',
  'deployed_at',
  'last_sync_at',
  'removed_at',
  'first_hit_at',
  'last_hit_at',
  'last_hit_report_ids',
  'last_validation_at',
  'validation_run_id',
  'error_message',
] as const;

/**
 * Build the deployed-on specific attributes of a relationship at creation time.
 * Status and counters always get a value so that filters and aggregations never see a missing field.
 */
export const buildDeployedOnCreationData = (input: Partial<Record<keyof DeployedOnAttributes, unknown>>): DeployedOnAttributes => {
  const data: DeployedOnAttributes = {
    deployment_status: isDeploymentStatus(input.deployment_status) ? input.deployment_status : DEPLOYMENT_STATUS_PENDING,
    hit_count: typeof input.hit_count === 'number' && input.hit_count >= 0 ? Math.trunc(input.hit_count) : 0,
    validation_status: isValidationStatus(input.validation_status) ? input.validation_status : VALIDATION_STATUS_NOT_REQUESTED,
  };
  OPTIONAL_DEPLOYED_ON_KEYS.forEach((key) => {
    const value = input[key];
    if (value !== undefined && value !== null && value !== '' && !(Array.isArray(value) && value.length === 0)) {
      (data as unknown as Record<string, unknown>)[key] = value;
    }
  });
  return data;
};

// Namespace of the stable hits sighting identifier (one sighting per indicator and security platform).
const HITS_SIGHTING_NAMESPACE = uuidv5('opencti-indicator-deployment-hits', OPENCTI_NAMESPACE);

export const hitsSightingStixId = (indicatorInternalId: string, platformInternalId: string) => {
  return `sighting--${uuidv5(`${indicatorInternalId}|${platformInternalId}`, HITS_SIGHTING_NAMESPACE)}`;
};

const VALIDATION_RESULT_SIGHTING_NAMESPACE = uuidv5('opencti-ioc-validation-result', OPENCTI_NAMESPACE);

// One sighting per request and pair: a replayed result never records the outcome twice.
export const validationResultSightingStixId = (requestInternalId: string, indicatorInternalId: string, platformInternalId: string) => {
  return `sighting--${uuidv5(`${requestInternalId}|${indicatorInternalId}|${platformInternalId}`, VALIDATION_RESULT_SIGHTING_NAMESPACE)}`;
};
