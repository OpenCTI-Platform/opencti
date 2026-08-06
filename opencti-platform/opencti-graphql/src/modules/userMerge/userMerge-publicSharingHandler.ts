import { getEntitiesMapFromCache } from '../../database/cache';
import { elRawCount } from '../../database/engine';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
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

export const USER_MERGE_PUBLIC_SHARING_HANDLER = 'public-sharing-user';

interface PublicSharingTarget {
  registerRow: string;
  entityType: string;
  userIdField: string;
  /** Wording used in the alert sentence. Not an i18n key: alerts are reported as-is. */
  noun: string;
}

/**
 * Mirrors the sharing configuration of the dataSharing module, which does not export it.
 * The list is asserted against the module's own entity types by the handler tests.
 */
const PUBLIC_SHARING_TARGETS: PublicSharingTarget[] = [
  { registerRow: 'feed.public-user-id', entityType: ENTITY_TYPE_FEED, userIdField: 'feed_public_user_id', noun: 'csv feed' },
  { registerRow: 'taxii-collection.public-user-id', entityType: ENTITY_TYPE_TAXII_COLLECTION, userIdField: 'taxii_public_user_id', noun: 'Taxii collection' },
  { registerRow: 'stream-collection.public-user-id', entityType: ENTITY_TYPE_STREAM_COLLECTION, userIdField: 'stream_public_user_id', noun: 'live stream' },
];

const fieldPaths = PUBLIC_SHARING_TARGETS.map((target) => `${target.entityType}.${target.userIdField}`);

const sharingQuery = (target: PublicSharingTarget, sourceId: string): Record<string, unknown> => ({
  bool: {
    must: [
      { term: { [`${target.userIdField}.keyword`]: sourceId } },
      { terms: { 'entity_type.keyword': [target.entityType] } },
    ],
  },
});

export interface UserMergeExposureDiff {
  addedMarkings: string[];
  removedMarkings: string[];
  addedOrganizations: string[];
  removedOrganizations: string[];
}

const names = (values: { id: string; name?: string; definition?: string }[]): string[] => {
  return values.map((value) => value.definition ?? value.name ?? value.id);
};

const difference = (left: string[], right: string[]): string[] => left.filter((value) => !right.includes(value));

/**
 * What anonymous consumers of the endpoint would see after the merge, compared to before.
 *
 * A public sharing endpoint serves data through the configured user's own access, so moving
 * the reference moves the exposure with it.
 */
export const userMergeExposureDiff = (source: AuthUser, target: AuthUser): UserMergeExposureDiff => {
  const sourceMarkings = names(source.allowed_marking ?? []);
  const targetMarkings = names(target.allowed_marking ?? []);
  const sourceOrganizations = names(source.organizations ?? []);
  const targetOrganizations = names(target.organizations ?? []);
  return {
    addedMarkings: difference(targetMarkings, sourceMarkings),
    removedMarkings: difference(sourceMarkings, targetMarkings),
    addedOrganizations: difference(targetOrganizations, sourceOrganizations),
    removedOrganizations: difference(sourceOrganizations, targetOrganizations),
  };
};

/**
 * Blocking is decided on what the endpoint gains, never on what it loses: a narrower exposure
 * is a functional regression, reported as an alert, not a confidentiality risk.
 *
 * Organizations count as much as markings. Once a platform organization is configured, what a
 * user reads is bounded by the organizations they participate to, so an organization gained by
 * the target widens what the endpoint serves anonymously.
 */
export const isExposureWidening = (diff: UserMergeExposureDiff): boolean => {
  return diff.addedMarkings.length > 0 || diff.addedOrganizations.length > 0;
};

const exposureMessage = (target: PublicSharingTarget, count: number, diff: UserMergeExposureDiff): string => {
  const parts = [
    diff.addedMarkings.length > 0 ? `markings gained: ${diff.addedMarkings.join(', ')}` : undefined,
    diff.removedMarkings.length > 0 ? `markings lost: ${diff.removedMarkings.join(', ')}` : undefined,
    diff.addedOrganizations.length > 0 ? `organizations gained: ${diff.addedOrganizations.join(', ')}` : undefined,
    diff.removedOrganizations.length > 0 ? `organizations lost: ${diff.removedOrganizations.join(', ')}` : undefined,
  ].filter((part) => part !== undefined);
  return `${count} ${target.noun}(s) will be served with the target user access (${parts.join('; ')})`;
};

const loadUser = async (context: AuthContext, userId: string): Promise<AuthUser | undefined> => {
  const users = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  return users.get(userId);
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
  reads: fieldPaths,
  writes: fieldPaths,
  compute: async ({ context, sourceId, targetId }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    const sourceUser = await loadUser(context, sourceId);
    const targetUser = await loadUser(context, targetId);
    const diff = sourceUser && targetUser ? userMergeExposureDiff(sourceUser, targetUser) : undefined;
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
      // Reported per endpoint: the decision is about a given endpoint becoming more exposed,
      // not about an abstract difference between two accounts.
      if (count > 0 && diff) {
        const widening = isExposureWidening(diff);
        if (widening || diff.removedMarkings.length > 0 || diff.addedOrganizations.length > 0 || diff.removedOrganizations.length > 0) {
          alerts.push({
            register_row_id: target.registerRow,
            kind: 'exposure',
            message: exposureMessage(target, count, diff),
            blocking: widening,
          });
        }
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
