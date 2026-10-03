import { elRawCount } from '../../database/engine';
import { isNotEmptyField } from '../../database/utils';
import type { AuthUser } from '../../types/user';
import { BYPASS, isServiceAccountUser } from '../../utils/access';
import { ENTITY_TYPE_FEED } from '../dataSharing/feed-types';
import { ENTITY_TYPE_STREAM_COLLECTION } from '../dataSharing/streamCollection-types';
import { ENTITY_TYPE_TAXII_COLLECTION } from '../dataSharing/taxiiCollection-types';
import { userMergeBulkUpdate } from './userMerge-bulk';
import {
  type UserMergeHandler,
  type UserMergeHandlerContext,
  type UserMergeHandlerPlan,
  type UserMergePlannedChange,
  type UserMergeRightsAlert,
  USER_MERGE_TARGET_INDICES,
} from './userMerge-handler';
import { type UserMergeProjectedRights, userMergeRightsDifference, type UserMergeRightsLabels, userMergeRightsNames } from './userMerge-rights';

export const USER_MERGE_PUBLIC_SHARING_HANDLER = 'public-sharing-user';

interface PublicSharingTarget {
  registerRow: string;
  entityType: string;
  userIdField: string;
  /** Flag that makes the endpoint anonymous. An endpoint can name a user while being private. */
  publicField: string;
  /** Wording used in the alert sentence. Not an i18n key: alerts are reported as-is. */
  noun: string;
}

/**
 * Mirrors the sharing configuration of the dataSharing module, which does not export it.
 * The list is asserted against the module's own entity types by the handler tests.
 */
const PUBLIC_SHARING_TARGETS: PublicSharingTarget[] = [
  { registerRow: 'feed.public-user-id', entityType: ENTITY_TYPE_FEED, userIdField: 'feed_public_user_id', publicField: 'feed_public', noun: 'csv feed' },
  { registerRow: 'taxii-collection.public-user-id', entityType: ENTITY_TYPE_TAXII_COLLECTION, userIdField: 'taxii_public_user_id', publicField: 'taxii_public', noun: 'Taxii collection' },
  { registerRow: 'stream-collection.public-user-id', entityType: ENTITY_TYPE_STREAM_COLLECTION, userIdField: 'stream_public_user_id', publicField: 'stream_public', noun: 'live stream' },
];

const fieldPaths = PUBLIC_SHARING_TARGETS.map((target) => `${target.entityType}.${target.userIdField}`);
const publicFieldPaths = PUBLIC_SHARING_TARGETS.map((target) => `${target.entityType}.${target.publicField}`);

const sharingQuery = (target: PublicSharingTarget, userId: string): Record<string, unknown> => ({
  bool: {
    must: [
      { term: { [`${target.userIdField}.keyword`]: userId } },
      { terms: { 'entity_type.keyword': [target.entityType] } },
    ],
  },
});

/**
 * The endpoints that are actually anonymous.
 *
 * The reference is rewritten on every endpoint naming the user, public or not — clearing it on the
 * private ones would leave them pointing at a user that no longer exists. Only the public ones are
 * an exposure though, so the alerts are counted apart: a private endpoint raising a blocking alert
 * would stop a merge that changes nothing anonymous consumers can read.
 */
const publicSharingQuery = (target: PublicSharingTarget, userId: string): Record<string, unknown> => ({
  bool: {
    must: [
      { term: { [`${target.userIdField}.keyword`]: userId } },
      { term: { [`${target.publicField}`]: true } },
      { terms: { 'entity_type.keyword': [target.entityType] } },
    ],
  },
});

export interface UserMergeExposureDiff {
  addedMarkings: string[];
  removedMarkings: string[];
  addedOrganizations: string[];
  removedOrganizations: string[];
  addedCapabilities: string[];
  removedCapabilities: string[];
  addedGroups: string[];
  removedGroups: string[];
  /**
   * A service account bypasses the authorized member filter entirely in `buildDataRestrictions`,
   * the same way `BYPASS` does, but it is a flag on the account and not a capability, so no set
   * comparison can report it. Both directions are carried, like every other set above: losing
   * the bypass narrows what the endpoint serves as silently as gaining it widens it.
   */
  gainedServiceAccount: boolean;
  lostServiceAccount: boolean;
}

export interface UserMergeServiceAccountTransition {
  gained: boolean;
  lost: boolean;
}

const NO_SERVICE_ACCOUNT_TRANSITION: UserMergeServiceAccountTransition = { gained: false, lost: false };

export const userMergeServiceAccountTransition = (
  sourceUser: AuthUser,
  targetUser: AuthUser,
): UserMergeServiceAccountTransition => ({
  gained: !isServiceAccountUser(sourceUser) && isServiceAccountUser(targetUser),
  lost: isServiceAccountUser(sourceUser) && !isServiceAccountUser(targetUser),
});

/**
 * What anonymous consumers of the endpoint would see after the merge, compared to before.
 *
 * A public sharing endpoint serves data through the configured user's own access, so the
 * exposure follows the rights the endpoint is served with. Both sides are taken from the
 * projection rather than from the users themselves: under UNION the target ends up with more
 * than it holds when the plan is computed, and comparing against its current rights would
 * announce losses that do not happen.
 *
 * All four sets are compared because `buildDataRestrictions` reads all four: capabilities short
 * circuit the marking and organization checks entirely, and groups decide which authorized member
 * entries the endpoint matches — a filter applied whatever the capabilities.
 */
export const userMergeExposureDiff = (
  before: UserMergeProjectedRights,
  after: UserMergeProjectedRights,
  serviceAccount: UserMergeServiceAccountTransition = NO_SERVICE_ACCOUNT_TRANSITION,
): UserMergeExposureDiff => ({
  addedMarkings: userMergeRightsDifference(after.markings, before.markings),
  removedMarkings: userMergeRightsDifference(before.markings, after.markings),
  addedOrganizations: userMergeRightsDifference(after.organizations, before.organizations),
  removedOrganizations: userMergeRightsDifference(before.organizations, after.organizations),
  addedCapabilities: userMergeRightsDifference(after.capabilities, before.capabilities),
  removedCapabilities: userMergeRightsDifference(before.capabilities, after.capabilities),
  addedGroups: userMergeRightsDifference(after.groups, before.groups),
  removedGroups: userMergeRightsDifference(before.groups, after.groups),
  gainedServiceAccount: serviceAccount.gained,
  lostServiceAccount: serviceAccount.lost,
});

/**
 * Blocking is decided on what the endpoint gains, never on what it loses: a narrower exposure
 * is a functional regression, reported as an alert, not a confidentiality risk.
 *
 * Organizations count as much as markings. Once a platform organization is configured, what a
 * user reads is bounded by the organizations they participate to, so an organization gained by
 * the target widens what the endpoint serves anonymously.
 */
export const isExposureWidening = (diff: UserMergeExposureDiff): boolean => {
  return diff.addedMarkings.length > 0 || diff.addedOrganizations.length > 0
    || diff.addedCapabilities.length > 0 || diff.addedGroups.length > 0
    || diff.gainedServiceAccount;
};

const exposureMessage = (
  target: PublicSharingTarget,
  count: number,
  diff: UserMergeExposureDiff,
  labels: UserMergeRightsLabels,
  served: string,
): string => {
  const parts = [
    diff.addedMarkings.length > 0 ? `markings gained: ${userMergeRightsNames(labels, diff.addedMarkings)}` : undefined,
    diff.removedMarkings.length > 0 ? `markings lost: ${userMergeRightsNames(labels, diff.removedMarkings)}` : undefined,
    diff.addedOrganizations.length > 0 ? `organizations gained: ${userMergeRightsNames(labels, diff.addedOrganizations)}` : undefined,
    diff.removedOrganizations.length > 0 ? `organizations lost: ${userMergeRightsNames(labels, diff.removedOrganizations)}` : undefined,
    diff.addedGroups.length > 0 ? `groups gained: ${userMergeRightsNames(labels, diff.addedGroups)}` : undefined,
    diff.removedGroups.length > 0 ? `groups lost: ${userMergeRightsNames(labels, diff.removedGroups)}` : undefined,
    // Named on its own because it does not widen the exposure, it removes its bounds.
    diff.addedCapabilities.includes(BYPASS) ? `${BYPASS} gained: the endpoint serves the whole platform` : undefined,
    diff.addedCapabilities.length > 0 ? `capabilities gained: ${diff.addedCapabilities.join(', ')}` : undefined,
    diff.removedCapabilities.length > 0 ? `capabilities lost: ${diff.removedCapabilities.join(', ')}` : undefined,
    diff.gainedServiceAccount ? 'service account gained: the endpoint serves every element whatever its authorized members' : undefined,
    diff.lostServiceAccount ? 'service account lost: the endpoint no longer bypasses the authorized members' : undefined,
  ].filter((part) => part !== undefined);
  return `${count} ${target.noun}(s) ${served} (${parts.join('; ')})`;
};

const isExposureReported = (diff: UserMergeExposureDiff): boolean => {
  return diff.addedMarkings.length > 0 || diff.removedMarkings.length > 0
    || diff.addedOrganizations.length > 0 || diff.removedOrganizations.length > 0
    || diff.addedCapabilities.length > 0 || diff.removedCapabilities.length > 0
    || diff.addedGroups.length > 0 || diff.removedGroups.length > 0
    || diff.gainedServiceAccount || diff.lostServiceAccount;
};

/**
 * What the rights sets cannot express.
 *
 * Authorized member entries naming the source are re-pointed to the target, and the source
 * individual is merged into the target one; both widen what the endpoint reads without changing
 * any of the sets above. It happens on every merge and whatever the strategy, so it is stated
 * rather than measured: counting the elements it unlocks would cost a scan of the whole platform
 * for a figure the operator cannot act on differently.
 *
 * The channels that open are always the counterpart's. An endpoint moving from the source to the
 * target starts reading through the target's entries and individual; one already configured with
 * the target keeps its reader and gains what the source brings to it.
 */
const memberAccessMessage = (
  target: PublicSharingTarget,
  count: number,
  counterpart: string,
  mergesIndividual: boolean,
  served: string,
): string => {
  const channels = [`the elements the ${counterpart} user is an authorized member of`];
  if (mergesIndividual) {
    channels.push('what its individual created');
  }
  return `${count} public ${target.noun}(s) ${served} will also serve ${channels.join(' and ')}`;
};

/**
 * Moves the user reference of the public sharing endpoints.
 *
 * Split from the scalar handler because the work is not the same: the value is rewritten the
 * same way, but the decision attached to it is a change in what anonymous consumers can read.
 * Clearing the field instead — the behaviour applied when a user is deleted — would leave the
 * endpoints public while falling back to SYSTEM_USER, which is the worst of both outcomes.
 */
export const userMergePublicSharingHandler: UserMergeHandler = {
  identifier: USER_MERGE_PUBLIC_SHARING_HANDLER,
  covers: PUBLIC_SHARING_TARGETS.map((target) => target.registerRow),
  reads: [...fieldPaths, ...publicFieldPaths],
  writes: fieldPaths,
  compute: async ({ sourceId, targetId, rights, sourceUser, targetUser }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    const transferred = userMergeExposureDiff(rights.source, rights.projected, userMergeServiceAccountTransition(sourceUser, targetUser));
    // The endpoints already configured with the target are a second exposed surface: the user
    // reference does not move, but the rights it is served with do as soon as the strategy adds
    // any. Under STRICT the projection equals the target and the diff is empty.
    const kept = userMergeExposureDiff(rights.target, rights.projected);
    const mergesSourceIndividual = isNotEmptyField(sourceUser.individual_id);
    const mergesTargetIndividual = isNotEmptyField(targetUser.individual_id);
    for (let i = 0; i < PUBLIC_SHARING_TARGETS.length; i += 1) {
      const target = PUBLIC_SHARING_TARGETS[i];
      const count = await elRawCount({
        index: USER_MERGE_TARGET_INDICES,
        body: { query: sharingQuery(target, sourceId) },
      });
      changes.push({
        register_row_id: target.registerRow,
        entity_type: target.entityType,
        count,
        exact: true,
        detail: target.userIdField,
      });
      const publicCount = count === 0 ? 0 : await elRawCount({
        index: USER_MERGE_TARGET_INDICES,
        body: { query: publicSharingQuery(target, sourceId) },
      });
      const keptPublicCount = await elRawCount({
        index: USER_MERGE_TARGET_INDICES,
        body: { query: publicSharingQuery(target, targetId) },
      });
      // Reported per endpoint: the decision is about a given endpoint becoming more exposed,
      // not about an abstract difference between two accounts.
      if (publicCount > 0 && isExposureReported(transferred)) {
        alerts.push({
          register_row_id: target.registerRow,
          kind: 'exposure',
          message: exposureMessage(target, publicCount, transferred, rights.labels, 'will be served with the target user access'),
          blocking: isExposureWidening(transferred),
        });
      }
      if (keptPublicCount > 0 && isExposureReported(kept)) {
        alerts.push({
          register_row_id: target.registerRow,
          kind: 'exposure',
          message: exposureMessage(target, keptPublicCount, kept, rights.labels, 'already configured with the target user have their exposure changed'),
          blocking: isExposureWidening(kept),
        });
      }
      if (publicCount > 0) {
        alerts.push({
          register_row_id: target.registerRow,
          kind: 'exposure',
          message: memberAccessMessage(target, publicCount, 'target', mergesTargetIndividual, 'transferred to the target user'),
        });
      }
      if (keptPublicCount > 0) {
        alerts.push({
          register_row_id: target.registerRow,
          kind: 'exposure',
          message: memberAccessMessage(target, keptPublicCount, 'source', mergesSourceIndividual, 'already configured with the target user'),
        });
      }
    }
    return { handler: USER_MERGE_PUBLIC_SHARING_HANDLER, changes, alerts };
  },
  apply: async ({ sourceId, targetId }: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = new Set(plan.changes.filter((change) => change.count > 0).map((change) => change.register_row_id));
    let updated = 0;
    for (let i = 0; i < PUBLIC_SHARING_TARGETS.length; i += 1) {
      const target = PUBLIC_SHARING_TARGETS[i];
      if (planned.has(target.registerRow)) {
        const result = await userMergeBulkUpdate(
          `${USER_MERGE_PUBLIC_SHARING_HANDLER}:${target.registerRow}`,
          USER_MERGE_TARGET_INDICES,
          {
            query: sharingQuery(target, sourceId),
            script: {
              source: `if (params.source.equals(ctx._source.${target.userIdField})) { ctx._source.${target.userIdField} = params.target; }`,
              lang: 'painless',
              params: { source: sourceId, target: targetId },
            },
          },
        );
        updated += result.updated;
      }
    }
    return updated;
  },
};
