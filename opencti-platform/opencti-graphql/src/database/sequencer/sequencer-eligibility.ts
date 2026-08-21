// POC ingestion sequencer (plan 0009, Stage B). Eligibility = the bypass matrix (plan Part 1.4 /
// B1): ALL conditions required, anything else takes today's direct path. The same context marker
// covers re-entrancy (the loop applying an intent) and the denylist of lock-holding mutations
// that reach the boundary without opts.locks (stixCoreObjectImportPush): both set
// context.sequencer before calling into the boundary. A missed denylist member is caught by the
// batch-lock safety net (lock timeout -> worker retry), it never corrupts.
import { getDraftContext } from '../../utils/draftContext';
import { isStixObject } from '../../schema/stixCoreObject';
import { isStixRelationship } from '../../schema/stixRelationship';
import { SEQUENCER_CONFIG } from './sequencer-config';
import type { AuthContext, AuthUser } from '../../types/user';

// Worker origin (D2): only pycti's import_item_with_retries sets the opencti-retry-number header,
// read into user.origin.call_retry_number. It is a STRING, "0" on the first attempt: test
// presence, never truthiness.
export const isWorkerOrigin = (user: AuthUser) => {
  const retry = user.origin?.call_retry_number;
  return retry !== undefined && retry !== null;
};

export const isSequencerEligible = (
  context: AuthContext,
  user: AuthUser,
  type: string,
  opts: { fromRule?: string; locks?: string[]; restore?: boolean } = {},
) => {
  if (!SEQUENCER_CONFIG.enabled) return false;
  // 5/6. re-entrancy and denylist: a marked context always runs direct
  if (context.sequencer) return false;
  // 1. worker origin only
  if (!isWorkerOrigin(user)) return false;
  // 2. STIX types only: internal objects always take the direct path
  if (!isStixObject(type) && !isStixRelationship(type)) return false;
  // 3. no special write context
  if (getDraftContext(context, user)) return false;
  if (opts.fromRule) return false;
  if (user.origin?.socket === 'internal') return false;
  // 4. not inside a held lock or a restore
  if (opts.locks && opts.locks.length > 0) return false;
  if (opts.restore) return false;
  return true;
};

// Marks a context so every boundary call below it runs direct. Used by the loop when applying an
// intent (re-entrancy) and by denylisted lock-holding mutations (stixCoreObjectImportPush).
export const sequencerScopedContext = (context: AuthContext, scope: 'applying' | 'bypass'): AuthContext => {
  return { ...context, sequencer: { scope } };
};
