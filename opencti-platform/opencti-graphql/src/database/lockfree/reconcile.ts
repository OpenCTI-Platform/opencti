// Two entities found to be one: today's mergeEntities, after a refresh so its searches see everything, then the
// loser's identity keys point to the winner. Used inline where today merges during a create (several objects
// matching one input), and by the settler for duplicates found after both were created.
import * as R from 'ramda';
import { lockfreeContext } from './context';
import { elRefreshIndices } from '../../database/engine';
import { mergeEntities } from '../../database/middleware';
import { READ_DATA_INDICES, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { identityKeys, type Owner, setKeys } from './identity';
import { mgetRaw, toElements } from './load';

export const reconcileEntities = async (losers: Owner[], winner: Owner, opts: { context?: AuthContext; user?: AuthUser } = {}) => {
  const candidates = losers.filter((l) => l.owner_id !== winner.owner_id);
  if (candidates.length === 0) return 0;
  const docs = await mgetRaw([...candidates, winner].map((o) => ({ id: o.owner_id, index: o.owner_index })));
  if (!docs.get(winner.owner_id)) return 0;
  const present = candidates.filter((l) => docs.get(l.owner_id));
  if (present.length === 0) return 0;
  const lost = await toElements(present.map((l) => docs.get(l.owner_id) as any));
  await elRefreshIndices([...READ_DATA_INDICES, ...READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED]);
  await mergeEntities(opts.context ?? lockfreeContext, opts.user ?? SYSTEM_USER, winner.owner_id, present.map((l) => l.owner_id), {});
  const keys = lost.flatMap((e: any) => [...identityKeys(e.entity_type, { ...e, stix_id: e.standard_id }), e.internal_id]);
  await setKeys(keys.map((key) => ({ key, owner: R.omit(['key', 'state'], winner) })));
  return present.length;
};
