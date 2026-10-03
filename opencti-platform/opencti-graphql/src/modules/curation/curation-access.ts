import type { AuthUser } from '../../types/user';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNMERGE } from '../../utils/access';
import { ACTION_MERGE, ACTION_RESOLVE_ATTRIBUTION, ACTION_UNMERGE, type BasicStoreEntityCurationProposal } from './curation-types';

/**
 * Whether the user may apply the proposal: the capability its recommended action needs, whatever decision applies
 * it. Checked when a proposal is applied, and before a background task applying proposals is created for the user.
 */
export const canUserApplyProposal = (user: AuthUser, proposal: Pick<BasicStoreEntityCurationProposal, 'recommended_action'>) => {
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE)) return false;
  if (proposal.recommended_action === ACTION_MERGE || proposal.recommended_action === ACTION_UNMERGE) {
    return isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMERGE);
  }
  // Resolving an attribution conflict deletes the attributions that are not kept.
  if (proposal.recommended_action === ACTION_RESOLVE_ATTRIBUTION) {
    return isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNDELETE);
  }
  return true;
};
