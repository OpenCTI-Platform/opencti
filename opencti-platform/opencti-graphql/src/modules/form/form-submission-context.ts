import { ForbiddenAccess } from '../../config/errors';
import { redisGetWork } from '../../database/redis';
import type { AuthContext, AuthUser } from '../../types/user';
import { KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNFORMINTAKE, KNOWLEDGE_KNUPDATE, SETTINGS_SETKILLCHAINPHASES, SETTINGS_SETLABELS } from '../../utils/access';

const hasCapability = (names: string[] | undefined, capability: string) => (names ?? []).some((name) => name.includes(capability));

// Capabilities of the main scope, plus the ones of the draft scope when the destination is a draft.
const scopeCapabilities = (user: AuthUser, withDraft: boolean) => [
  ...user.capabilities.map((capability) => capability.name),
  ...(withDraft ? (user.capabilitiesInDraft ?? []).map((capability) => capability.name) : []),
];

/**
 * Can the user write the result of a form in this destination?
 * Main: Create / Update knowledge or the form capability, granted in the main scope.
 * Draft: the same, granted in the main or in the draft scope, or Import knowledge granted in the draft scope.
 */
export const canSubmitFormTo = (user: AuthUser, isDraft: boolean): boolean => {
  const names = scopeCapabilities(user, isDraft);
  if ([KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNFORMINTAKE].some((capability) => hasCapability(names, capability))) {
    return true;
  }
  // Before the form capability, formSubmit let a user with only Import knowledge granted in the draft scope submit
  // forms into a draft (forDraft: KNASKIMPORT in the @auth directive, which is still the case). Keep it: refusing them
  // here would turn a behavior of the API into an error. This grants nothing else: the import of the submission is
  // only verified (and given Create / Update knowledge) for an applicant who holds the form capability.
  return isDraft && hasCapability((user.capabilitiesInDraft ?? []).map((capability) => capability.name), KNOWLEDGE_KNASKIMPORT);
};

export interface FormSubmissionSideEffects {
  pendingLabels: number; // labels created by the submission
  pendingKillChainPhases: number; // objects created by the submission that carry a kill chain phase
}

export const checkFormSubmissionAccess = (user: AuthUser, isDraft: boolean, { pendingLabels, pendingKillChainPhases }: FormSubmissionSideEffects): void => {
  if (!canSubmitFormTo(user, isDraft)) {
    throw ForbiddenAccess('You are not allowed to submit forms in this destination.', { isDraft });
  }
  // Only Create / Update knowledge is given by the form capability: creating a label is still a right of its own.
  if (pendingLabels > 0 && !hasCapability(scopeCapabilities(user, isDraft), SETTINGS_SETLABELS)) {
    throw ForbiddenAccess('You are not allowed to create labels.', { capability: SETTINGS_SETLABELS });
  }
  // The import upserts the kill chain phases of the objects it creates, which needs the right to manage them: refuse
  // up front rather than lose the objects when the import is refused.
  if (pendingKillChainPhases > 0 && !hasCapability(scopeCapabilities(user, isDraft), SETTINGS_SETKILLCHAINPHASES)) {
    throw ForbiddenAccess('You are not allowed to attach kill chain phases to the objects created in a form.', { capability: SETTINGS_SETKILLCHAINPHASES });
  }
};

/**
 * Is this request the import of a Form Intake submission made by a user who submits forms with the form
 * capability? All of this must hold, the work id alone grants nothing:
 *  - the caller is a privileged credential (the worker) that impersonates the applicant,
 *  - the work is alive and was created by a form submission of this very applicant,
 *  - the request targets the draft the submission created (or no draft when it created none),
 *  - the applicant holds the form capability for that destination.
 *
 * The draft of the request is the opencti-draft-id header, or the current draft of the applicant when the header is
 * absent. It must equal the draft bound to the work, whichever way: an applicant with a current draft of their
 * own, whose submission created none, is not verified when the worker sends no draft header (the worker sets the
 * header to None for a bundle without draft_id, which the http client drops). The import then fails closed:
 * never a grant, only a refusal.
 */
export const isVerifiedFormSubmission = async (context: AuthContext): Promise<boolean> => {
  const { user, workId } = context;
  if (!user || !workId) return false;
  const isImpersonated = context.real_authentication_id !== undefined && context.real_authentication_id !== user.id;
  if (!isImpersonated) return false;
  const work = await redisGetWork(workId);
  if (work?.is_initialized !== 'true' || !work.form_id || work.form_applicant_id !== user.id) return false;
  const draftId = work.form_draft_id || undefined;
  if ((context.draft_context || undefined) !== draftId) return false;
  return hasCapability(scopeCapabilities(user, draftId !== undefined), KNOWLEDGE_KNFORMINTAKE);
};
