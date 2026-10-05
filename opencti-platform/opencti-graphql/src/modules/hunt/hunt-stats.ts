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
  // Hits of the last run never seen before for the hunt on its security platform
  last_new_hits_count?: number | null;
  next_run_at?: string | null;
  hunt_pir_armed?: boolean | null;
  hunt_pir_armed_at?: string | null;
}

const ASSIGN_PATCH = 'for (entry in params.patch.entrySet()) { ctx._source[entry.getKey()] = entry.getValue(); }';
// Compared and written in one script: two runs finalized at the same time never regress the statistics
const ASSIGN_PATCH_IF_NEWER = 'def current = ctx._source.last_run_at; '
  + 'if (current != null && ZonedDateTime.parse(current.toString()).toInstant().toEpochMilli() > params.at) { ctx.op = \'noop\'; } '
  + `else { ${ASSIGN_PATCH} }`;

/**
 * Run statistics of a hunt (last run, last hits, next run) are platform computed values:
 * they are written directly in the index, without stream event, history entry or updated_at change.
 * With `onlyIfNewer`, the patch is skipped when the hunt already records a later run than `patch.last_run_at`.
 */
export const updateHuntRunInformation = async (
  context: AuthContext,
  huntId: string,
  patch: HuntRunInformationPatch,
  options: { onlyIfNewer?: boolean } = {},
) => {
  const hunt = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, huntId, { type: ENTITY_TYPE_HUNT });
  if (!hunt) {
    return;
  }
  const conditional = options.onlyIfNewer === true && !!patch.last_run_at;
  const source = conditional ? ASSIGN_PATCH_IF_NEWER : ASSIGN_PATCH;
  const params = conditional ? { patch, at: new Date(patch.last_run_at as string).getTime() } : { patch };
  await elUpdate(context, hunt._index, hunt.internal_id, { script: { source, lang: 'painless', params } });
};
