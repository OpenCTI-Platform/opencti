import { redisGetWork } from '../../src/database/redis';
import { CONNECTOR_INTERNAL_ENRICHMENT } from '../../src/schema/general';
import type { AuthContext } from '../../src/types/user';
import { testContext } from './testQuery';

/**
 * Build the context of a worker writing under a work, with the touched ids tracking fields that
 * createGraphqlContext derives from the work hash stored in Redis.
 * @param workId the work the writes are made under
 * @param extraContext fields added to the context, such as a draft context
 */
export const buildWorkerContext = async (workId: string, extraContext: Partial<AuthContext> = {}): Promise<AuthContext> => {
  const work = await redisGetWork(workId);
  return {
    ...testContext,
    workId,
    trackWorkTouchedIds: !!work.investigation_id && work.event_type === CONNECTOR_INTERNAL_ENRICHMENT,
    enrichedEntityId: work.enriched_entity_id,
    ...extraContext,
  };
};
