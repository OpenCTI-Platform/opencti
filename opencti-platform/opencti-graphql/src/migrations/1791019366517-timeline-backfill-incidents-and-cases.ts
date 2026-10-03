import { logMigration } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { fullEntitiesList } from '../database/middleware-loader';
import type { BasicStoreEntity } from '../types/store';
import { TIMELINE_CONTAINER_TYPES } from '../modules/timeline/timeline-types';
import { enqueueTimelineRegeneration } from '../modules/timeline/timeline-queue';

const message = '[MIGRATION] Schedule the timeline backfill of incidents and cases';

// The migration only schedules the work: the timeline manager regenerates the scheduled
// containers progressively, by batches, so that the startup is never blocked by the backfill.
export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  let scheduled = 0;
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, TIMELINE_CONTAINER_TYPES, {
    baseData: true,
    callback: async (containers: BasicStoreEntity[]) => {
      await enqueueTimelineRegeneration(containers.map((container) => container.internal_id), 0);
      scheduled += containers.length;
      logMigration.info(`${message} > ${scheduled} incidents and cases scheduled`);
      return true;
    },
  } as any);
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms (${scheduled} scheduled)`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
