import {
  DEPLOYMENT_STATUS_PENDING,
  DEPLOYMENT_STATUSES,
  type DeployedOnAttributes,
  type DeploymentStatus,
  VALIDATION_STATUS_NOT_REQUESTED,
  VALIDATION_STATUSES,
  type ValidationStatus,
} from './indicatorDeployment-types';

export const isDeploymentStatus = (value: unknown): value is DeploymentStatus => {
  return typeof value === 'string' && (DEPLOYMENT_STATUSES as readonly string[]).includes(value);
};

export const isValidationStatus = (value: unknown): value is ValidationStatus => {
  return typeof value === 'string' && (VALIDATION_STATUSES as readonly string[]).includes(value);
};

const OPTIONAL_DEPLOYED_ON_KEYS = [
  'external_id',
  'deployed_at',
  'last_sync_at',
  'removed_at',
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
