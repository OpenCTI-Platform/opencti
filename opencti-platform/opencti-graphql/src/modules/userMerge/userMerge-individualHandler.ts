import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { BUS_TOPICS } from '../../config/conf';
import { notify } from '../../database/redis';
import { fullEntitiesList, storeLoadById } from '../../database/middleware-loader';
import { mergeEntities, patchAttribute } from '../../database/middleware';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../schema/stixDomainObject';
import { FilterMode } from '../../generated/graphql';
import type { BasicStoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { USER_MERGE_SILENT_WRITE } from './userMerge-handler';
import type { UserMergeHandler, UserMergeHandlerContext, UserMergeHandlerPlan, UserMergePlannedChange, UserMergeRightsAlert } from './userMerge-handler';

export const USER_MERGE_INDIVIDUAL_HANDLER = 'user-individual';

const CONTACT_INFORMATION = 'contact_information';

/** No register row describes this link: it is a join on the email, stored in no document. */
const INDIVIDUAL_ROW = 'individual.contact-information';

interface IndividualPlan {
  /** The individual the target ends up with, if there is one at all. */
  survivor?: BasicStoreEntity;
  /** Individuals folded into the survivor. */
  merged: BasicStoreEntity[];
  /** Whether the survivor still carries the source email and has to be re-pointed. */
  repoint: boolean;
  /** Every individual carrying either email, used to report an ambiguous join. */
  all: BasicStoreEntity[];
}

const individualsOf = async (context: AuthContext, emails: string[]): Promise<BasicStoreEntity[]> => {
  const filters = { mode: FilterMode.And, filters: [{ key: [CONTACT_INFORMATION], values: emails }], filterGroups: [] };
  return fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], {
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    filters,
    noFiltersChecking: true,
  });
};

/**
 * Which individual survives, and what has to be folded into it.
 *
 * The target's own individual is preferred so that nothing it already carries has to move. When
 * the target has none, one of the source's is kept and re-pointed, which is cheaper than
 * creating an individual and merging into it, and gives the same end state.
 */
const readIndividualPlan = async (context: AuthContext, sourceEmail: string, targetEmail: string): Promise<IndividualPlan> => {
  const all = await individualsOf(context, [sourceEmail, targetEmail]);
  const onTarget = all.filter((individual) => individual.contact_information === targetEmail);
  const onSource = all.filter((individual) => individual.contact_information === sourceEmail);
  const survivor = onTarget[0] ?? onSource[0];
  if (!survivor) {
    return { merged: [], repoint: false, all };
  }
  const merged = all.filter((individual) => individual.internal_id !== survivor.internal_id);
  return { survivor, merged, repoint: onTarget.length === 0, all };
};

/**
 * The identity fields the platform keeps mirrored from the user onto its individual.
 *
 * Every user update re-applies them alongside the email (`middleware.updateAttributeMetaResolved`),
 * so a re-point moving the email alone would leave the survivor answering to the target address
 * under the source name — until the next edit of the target user silently repairs it.
 *
 * They are read from the stored user rather than from the session one, which carries the name
 * but neither the first nor the last name.
 */
const identityOf = async (context: AuthContext, targetUser: AuthUser): Promise<Record<string, unknown>> => {
  type StoredUserIdentity = BasicStoreEntity & { firstname?: string; lastname?: string };
  const stored = await storeLoadById<StoredUserIdentity>(context, SYSTEM_USER, targetUser.internal_id, ENTITY_TYPE_USER);
  return {
    name: stored.name,
    x_opencti_firstname: stored.firstname,
    x_opencti_lastname: stored.lastname,
  };
};

const ambiguousJoinAlert = (email: string, count: number): UserMergeRightsAlert => ({
  register_row_id: INDIVIDUAL_ROW,
  kind: 'rights',
  message: `${count} individuals carry ${email}; the join that resolves a user individual is not deterministic on that email,`
    + ' and they are folded into one',
});

/**
 * Merges the individual of the source user into the target's.
 *
 * The individual is part of the visibility filter, not a profile card: a user sees their own
 * individual and what it created. PR3 moves `creator_id` to the target, but the notes and
 * opinions authored by the source still carry the source individual as `createdBy`, so without
 * this the target would own objects it cannot read, and would fail the collaborative ownership
 * check on every one of them.
 *
 * No register row covers this: `individual_id` is recomputed at every session build by joining
 * `contact_information` against `user_email`, so the link exists in no document.
 */
export const userMergeIndividualHandler: UserMergeHandler = {
  identifier: USER_MERGE_INDIVIDUAL_HANDLER,
  covers: [],
  reads: [
    `${ENTITY_TYPE_IDENTITY_INDIVIDUAL}.${CONTACT_INFORMATION}`,
    `${ENTITY_TYPE_USER}.name`,
    `${ENTITY_TYPE_USER}.firstname`,
    `${ENTITY_TYPE_USER}.lastname`,
  ],
  writes: [
    `${ENTITY_TYPE_IDENTITY_INDIVIDUAL}.${CONTACT_INFORMATION}`,
    `${ENTITY_TYPE_IDENTITY_INDIVIDUAL}.name`,
    `${ENTITY_TYPE_IDENTITY_INDIVIDUAL}.x_opencti_firstname`,
    `${ENTITY_TYPE_IDENTITY_INDIVIDUAL}.x_opencti_lastname`,
  ],
  compute: async ({ context, sourceUser, targetUser }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    const plan = await readIndividualPlan(context, sourceUser.user_email, targetUser.user_email);
    changes.push({
      register_row_id: INDIVIDUAL_ROW,
      entity_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL,
      count: plan.merged.length,
      exact: true,
      detail: 'folded into the target individual',
    });
    changes.push({
      register_row_id: INDIVIDUAL_ROW,
      entity_type: ENTITY_TYPE_IDENTITY_INDIVIDUAL,
      count: plan.repoint ? 1 : 0,
      exact: true,
      detail: 're-pointed to the target email and identity',
    });
    const individuals = plan.all;
    [sourceUser.user_email, targetUser.user_email].forEach((email) => {
      const carrying = individuals.filter((individual) => individual.contact_information === email).length;
      if (carrying > 1) {
        alerts.push(ambiguousJoinAlert(email, carrying));
      }
    });
    return { handler: USER_MERGE_INDIVIDUAL_HANDLER, changes, alerts };
  },
  apply: async ({ context, sourceUser, targetUser }: UserMergeHandlerContext): Promise<number> => {
    const plan = await readIndividualPlan(context, sourceUser.user_email, targetUser.user_email);
    if (!plan.survivor) {
      return 0;
    }
    let updated = 0;
    if (plan.merged.length > 0) {
      await mergeEntities(context, SYSTEM_USER, plan.survivor.internal_id, plan.merged.map((individual) => individual.internal_id), USER_MERGE_SILENT_WRITE);
      updated += plan.merged.length;
    }
    if (plan.repoint) {
      // The survivor still carries the source email, and a user answers to it until the merge
      // completes: without the bypass `patchAttribute` refuses to touch an individual bound to a
      // user. This is the synchronized user/individual update the flag exists for.
      await patchAttribute(context, SYSTEM_USER, plan.survivor.internal_id, ENTITY_TYPE_IDENTITY_INDIVIDUAL, {
        [CONTACT_INFORMATION]: targetUser.user_email,
        ...await identityOf(context, targetUser),
      }, { bypassIndividualUpdate: true, ...USER_MERGE_SILENT_WRITE });
      updated += 1;
    }
    // The individual is denormalized onto the user as `individual_id` at session build, so a
    // target that had none stays cached without one — failing the very ownership checks this
    // handler exists to repair, and letting `resolveUserIndividual` create a second individual.
    if (updated > 0) {
      await notify(BUS_TOPICS[ENTITY_TYPE_USER].EDIT_TOPIC, [sourceUser, targetUser], SYSTEM_USER);
    }
    return updated;
  },
};
