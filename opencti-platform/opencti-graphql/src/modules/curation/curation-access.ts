import type { AuthUser } from '../../types/user';
import { isUserHasCapability, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNMERGE, SETTINGS_SETCUSTOMIZATION } from '../../utils/access';
import {
  ACTION_ADD_ALIASES,
  ACTION_MERGE,
  ACTION_RESOLVE_ATTRIBUTION,
  ACTION_UNMERGE,
  type BasicStoreEntityCurationProposal,
  DECISION_ALIAS,
  DECISION_MERGE,
} from './curation-types';

/**
 * The action applying a proposal runs. An adjudication decision applied to a duplicate proposal decides it: `merge`
 * merges the subjects and `alias` adds the other names as aliases of the target, whatever the proposal recommended.
 * Without a decision (an analyst's accept, a policy), the recommended action runs.
 */
export const effectiveProposalAction = (proposal: Pick<BasicStoreEntityCurationProposal, 'recommended_action'>, decision?: string | null) => {
  const isDuplicateAction = proposal.recommended_action === ACTION_MERGE || proposal.recommended_action === ACTION_ADD_ALIASES;
  if (isDuplicateAction && decision === DECISION_MERGE) return ACTION_MERGE;
  if (isDuplicateAction && decision === DECISION_ALIAS) return ACTION_ADD_ALIASES;
  return proposal.recommended_action;
};

/** Whether an adjudication decided the action a proposal ran: a merge decision the merge, an alias decision the aliases. */
export const adjudicationDecidesAction = (decision: string | null | undefined, action: string) => (
  (decision === DECISION_MERGE && action === ACTION_MERGE) || (decision === DECISION_ALIAS && action === ACTION_ADD_ALIASES)
);

/**
 * Whether the user may apply the proposal: the capability of the action it runs (see effectiveProposalAction). Checked
 * when a proposal is applied, and before a background task applying proposals is created for the user.
 */
export const canUserApplyProposal = (user: AuthUser, proposal: Pick<BasicStoreEntityCurationProposal, 'recommended_action'>, decision?: string | null) => {
  if (!isUserHasCapability(user, KNOWLEDGE_KNUPDATE)) return false;
  const action = effectiveProposalAction(proposal, decision);
  if (action === ACTION_MERGE || action === ACTION_UNMERGE) {
    return isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNMERGE);
  }
  // Resolving an attribution conflict deletes the attributions that are not kept.
  if (action === ACTION_RESOLVE_ATTRIBUTION) {
    return isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNDELETE);
  }
  return true;
};

/**
 * Whether accepting the proposal takes a choice a user makes on that proposal alone: which attribution of an attribution
 * contradiction to keep. Such a proposal is accepted one at a time, never in a bulk accept nor by a policy.
 */
export const isProposalChoiceRequired = (proposal: Pick<BasicStoreEntityCurationProposal, 'recommended_action'>) => {
  return proposal.recommended_action === ACTION_RESOLVE_ATTRIBUTION;
};

/**
 * Whether the user may apply proposals in the name of a curation policy: an application by a policy counts against the
 * policy and is recorded as automatic, so it takes the right to manage policies, the one that starts a policy run. The
 * curation manager runs scheduled policies as a bypass user.
 */
export const canUserApplyPolicy = (user: AuthUser) => isUserHasCapability(user, SETTINGS_SETCUSTOMIZATION);

/**
 * The action a revert runs is the opposite of what was applied, whatever the proposal recommended: every merge is
 * recorded, so a merge record means an unmerge; a duplicate proposal applied without one added aliases.
 */
export const revertedProposalAction = (proposal: Pick<BasicStoreEntityCurationProposal, 'recommended_action' | 'merge_record_id'>) => {
  if (proposal.merge_record_id) return ACTION_UNMERGE;
  if (proposal.recommended_action === ACTION_MERGE) return ACTION_ADD_ALIASES;
  return proposal.recommended_action;
};

export const canUserRevertProposal = (user: AuthUser, proposal: Pick<BasicStoreEntityCurationProposal, 'recommended_action' | 'merge_record_id'>) => {
  return canUserApplyProposal(user, { recommended_action: revertedProposalAction(proposal) });
};
