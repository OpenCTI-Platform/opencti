import type { StoreRelation } from '../../types/store';
import type { StixDeployedOnExtension } from '../../types/stix-2-1-sro';
import { convertToStixDate } from '../../database/stix-converter-utils';
import type { StixDate } from '../../types/stix-2-1-common';
import { RELATION_DEPLOYED_ON, type StoreRelationDeployedOn } from './indicatorDeployment-types';

const toStixDate = (value: Date | string | null | undefined): StixDate => convertToStixDate(value ?? undefined) as StixDate;

/**
 * Deployment state carried in the OpenCTI extension of a deployed-on relationship,
 * so stream consumers and synchronized platforms receive the lifecycle.
 * Returns an empty object for every other relationship type.
 */
export const convertDeployedOnToStixExtension = (instance: StoreRelation): StixDeployedOnExtension => {
  if (instance.relationship_type !== RELATION_DEPLOYED_ON) {
    return {};
  }
  const deployment = instance as StoreRelationDeployedOn;
  return {
    deployment_status: deployment.deployment_status,
    external_id: deployment.external_id ?? undefined,
    deployed_at: toStixDate(deployment.deployed_at),
    last_sync_at: toStixDate(deployment.last_sync_at),
    removed_at: toStixDate(deployment.removed_at),
    hit_count: deployment.hit_count,
    first_hit_at: toStixDate(deployment.first_hit_at),
    last_hit_at: toStixDate(deployment.last_hit_at),
    // The reports counted at the last hit: a synchronized platform tells their retries apart as the source does
    last_hit_report_ids: deployment.last_hit_report_ids?.length ? deployment.last_hit_report_ids : undefined,
    validation_status: deployment.validation_status,
    last_validation_at: toStixDate(deployment.last_validation_at),
    validation_run_id: deployment.validation_run_id ?? undefined,
    error_message: deployment.error_message ?? undefined,
  };
};
