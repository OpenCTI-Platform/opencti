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
import { OPENCTI_NAMESPACE } from '../../schema/general';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';

export const isDeploymentStatus = (value: unknown): value is DeploymentStatus => {
  return typeof value === 'string' && (DEPLOYMENT_STATUSES as readonly string[]).includes(value);
};

export const isValidationStatus = (value: unknown): value is ValidationStatus => {
  return typeof value === 'string' && (VALIDATION_STATUSES as readonly string[]).includes(value);
};

type MarkedElement = { [RELATION_OBJECT_MARKING]?: string[] | null };
type RestrictedElement = MarkedElement & { [RELATION_GRANTED_TO]?: string[] | null; restricted_members?: unknown[] | null };

/**
 * Markings of a relationship generated for an (indicator, security platform) pair: the deployment, its hits sighting
 * and the validation result sightings. Access to a relationship is checked on its own markings, so it carries those of
 * both ends: a reader of the indicator never sees the deployments, hits or results of a more restricted platform.
 */
export const pairMarkings = (indicator: MarkedElement, platform: MarkedElement): string[] => {
  return [...new Set([...(indicator[RELATION_OBJECT_MARKING] ?? []), ...(platform[RELATION_OBJECT_MARKING] ?? [])])];
};

/**
 * Whether every reader of the indicator can read the deployment. The counters stored on the indicator only count such
 * deployments, so they never reveal the deployments, hits or results a reader of the indicator cannot read:
 * - markings: the deployment carries no marking the indicator does not carry;
 * - organizations: the deployment is shared with every organization the indicator is shared with (an indicator shared
 *   with no organization is only read by the platform organization, which reads every deployment);
 * - authorized members: neither has any, since authorized members of the indicator read it whatever their
 *   organization and nothing proves they can read the deployment (such deployments are left out of the counters).
 * The same holds for the security platform of the deployment, whose own restrictions are checked as well: a
 * deployment created by a connector is shared with the connector organizations, not with those of the platform.
 */
export const isReadableWithIndicator = (deployment: RestrictedElement, indicator: RestrictedElement, platform?: RestrictedElement) => {
  if ((indicator.restricted_members ?? []).length > 0) {
    return false;
  }
  const indicatorMarkings = indicator[RELATION_OBJECT_MARKING] ?? [];
  const indicatorOrganizations = indicator[RELATION_GRANTED_TO] ?? [];
  const readableByIndicatorReaders = (element: RestrictedElement) => {
    const elementOrganizations = element[RELATION_GRANTED_TO] ?? [];
    return (element[RELATION_OBJECT_MARKING] ?? []).every((marking) => indicatorMarkings.includes(marking))
      && (element.restricted_members ?? []).length === 0
      && indicatorOrganizations.every((organization) => elementOrganizations.includes(organization));
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
    if (value !== undefined && value !== null && value !== '') {
      (data as unknown as Record<string, unknown>)[key] = value;
    }
  });
  return data;
};

const VALIDATION_RESULT_SIGHTING_NAMESPACE = uuidv5('opencti-ioc-validation-result', OPENCTI_NAMESPACE);

// One sighting per request and pair: a replayed result never records the outcome twice.
export const validationResultSightingStixId = (requestInternalId: string, indicatorInternalId: string, platformInternalId: string) => {
  return `sighting--${uuidv5(`${requestInternalId}|${indicatorInternalId}|${platformInternalId}`, VALIDATION_RESULT_SIGHTING_NAMESPACE)}`;
};
