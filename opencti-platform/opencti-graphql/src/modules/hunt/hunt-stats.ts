import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { elUpdate } from '../../database/engine';
import { internalLoadById } from '../../database/middleware-loader';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_HUNT } from './hunt-types';

export interface HuntRunInformationPatch {
  last_run_at?: string | null;
  last_run_status?: string | null;
  last_hits_count?: number | null;
  next_run_at?: string | null;
  hunt_pir_armed?: boolean | null;
  hunt_pir_armed_at?: string | null;
}

/**
 * Run statistics of a hunt (last run, last hits, next run) are platform computed values:
 * they are written directly in the index, without stream event, history entry or updated_at change.
 */
export const updateHuntRunInformation = async (context: AuthContext, huntId: string, patch: HuntRunInformationPatch) => {
  const hunt = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, huntId, { type: ENTITY_TYPE_HUNT });
  if (!hunt) {
    return;
  }
  const source = 'for (entry in params.patch.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }';
  await elUpdate(context, hunt._index, hunt.internal_id, { script: { source, lang: 'painless', params: { patch } } });
};
