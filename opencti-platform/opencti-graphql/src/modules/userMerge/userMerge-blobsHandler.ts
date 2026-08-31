import { fromBase64, toBase64 } from '../../database/utils';
import { userMergeBulkRewrite, type UserMergeRewriteCandidate, userMergeScanPagesForRewrite } from './userMerge-bulk';
import {
  type UserMergeHandler,
  type UserMergeHandlerContext,
  type UserMergeHandlerPlan,
  type UserMergePlannedChange,
  type UserMergeRightsAlert,
  USER_MERGE_TARGET_INDICES,
} from './userMerge-handler';
import { remapUserInJsonString, remapUserInJsonValue } from './userMerge-jsonRemap';
import { USER_MERGE_BLOB_TARGETS, USER_MERGE_DRAFT_PATCH_TARGET, type UserMergeBlobTarget, userMergeBlobCoveredRows, userMergeBlobFieldPaths } from './userMerge-blobTargets';

export const USER_MERGE_BLOBS_HANDLER = 'blob-user-references';

/**
 * Why a document holding the source id was left untouched.
 *
 * `unparsable` is a payload the platform cannot read back — a corrupt manifest, a truncated
 * definition. `textual` is one that reads back fine but carries the id inside a value rather
 * than as one, typically a raw uuid typed into a free-text search saved in a widget. Neither is
 * rewritten, and the two are reported apart because they call for opposite follow-ups.
 */
type RewriteRejection = 'unparsable' | 'textual';

/**
 * A rejection is a string, so `typeof` cannot tell it apart from a rewritten payload. Every
 * caller goes through this guard rather than a type test that would silently let the marker
 * through and write it as content.
 */
const isRejection = (value: unknown): value is RewriteRejection => value === 'unparsable' || value === 'textual';

interface BlobRewrite {
  candidate: UserMergeRewriteCandidate;
  doc: Record<string, unknown>;
}

interface TargetOutcome {
  rewrites: BlobRewrite[];
  unparsable: number;
  textual: number;
  /** Documents in a lifecycle state the merge precondition rules out. */
  active: number;
}

const emptyOutcome = (): TargetOutcome => ({ rewrites: [], unparsable: 0, textual: 0, active: 0 });

/**
 * Documents this target has to look at.
 *
 * Only `json` can be pre-selected. Its field maps to `text` with no keyword sub-field, so a term
 * query never matches, but the standard analyzer splits the id on its dashes and a phrase match
 * on the id is a match on that token sequence — a pre-selection, confirmed once parsed.
 *
 * The other three shapes cannot be pre-selected at all, for reasons that are properties of the
 * mapping rather than of the query: a Base64 never holds the id in clear, and `flat` and
 * `nested` bury it where a top-level phrase match does not reach. Every document of the type is
 * read and discarded in memory instead, which the volume of these configuration entities
 * affords.
 */
const selectionQuery = (target: UserMergeBlobTarget, sourceId: string): Record<string, unknown> => {
  const must: Record<string, unknown>[] = [{ terms: { 'entity_type.keyword': [target.entityType] } }];
  if (target.shape === 'json') {
    must.push({ match_phrase: { [target.path]: sourceId } });
  }
  return { bool: { must } };
};

const isActive = (target: UserMergeBlobTarget, source: Record<string, any>): boolean => {
  if (!target.activity) {
    return false;
  }
  const matches = source[target.activity.path] === target.activity.equals;
  return target.activity.negate ? !matches : matches;
};

/**
 * A serialized JSON field: parse, walk, re-serialize. Exported because every shape ends up here,
 * including the draft patch, whose replay against live data is what makes a wrong rewrite costly.
 */
export const rewriteJson = (raw: unknown, sourceId: string, targetId: string): string | RewriteRejection | undefined => {
  if (typeof raw !== 'string' || !raw.includes(sourceId)) {
    return undefined;
  }
  const result = remapUserInJsonString(raw, sourceId, targetId);
  if (!result.changed) {
    return result.parsed ? 'textual' : 'unparsable';
  }
  return result.json;
};

/**
 * A Base64 of a JSON: decode, remap, re-encode.
 *
 * The decode is what makes this shape expensive — the id is not in the stored value, so the
 * decision to skip a document can only be taken after decoding it.
 */
const rewriteBase64 = (raw: unknown, sourceId: string, targetId: string): string | RewriteRejection | undefined => {
  if (typeof raw !== 'string' || raw.length === 0) {
    return undefined;
  }
  const decoded = fromBase64(raw);
  if (!decoded) {
    return 'unparsable';
  }
  const rewritten = rewriteJson(decoded, sourceId, targetId);
  if (rewritten === undefined || isRejection(rewritten)) {
    return rewritten;
  }
  return toBase64(rewritten);
};

/**
 * A payload the platform stores as an object rather than a string: walk it directly, with no
 * parse step to fail on.
 */
const rewriteObject = (raw: unknown, sourceId: string, targetId: string): unknown | undefined => {
  if (raw === null || typeof raw !== 'object') {
    return undefined;
  }
  const result = remapUserInJsonValue(raw, sourceId, targetId);
  return result.changed ? result.payload : undefined;
};

/**
 * A `nested` sub-document, single or repeated, whose `content` holds the serialized definition.
 *
 * Only `content` is rewritten. The sibling `createdBy` is a user reference too, but the register
 * gives it a row of its own and the scalar handler already answers for it — walking the whole
 * sub-document here would write the same field twice.
 */
const rewriteNestedJson = (raw: unknown, sourceId: string, targetId: string): unknown | RewriteRejection | undefined => {
  const versions = Array.isArray(raw) ? raw : [raw];
  if (versions.some((version) => version === null || typeof version !== 'object')) {
    return undefined;
  }
  let changed = false;
  let rejection: RewriteRejection | undefined;
  const rewritten = versions.map((version: Record<string, unknown>) => {
    const content = rewriteJson(version.content, sourceId, targetId);
    if (isRejection(content)) {
      rejection = content;
      return version;
    }
    if (content === undefined) {
      return version;
    }
    changed = true;
    return { ...version, content };
  });
  if (!changed) {
    return rejection;
  }
  return Array.isArray(raw) ? rewritten : rewritten[0];
};

/** Single entry point per target. Exported so each shape can be exercised without Elasticsearch. */
export const rewriteTarget = (
  candidate: UserMergeRewriteCandidate,
  target: UserMergeBlobTarget,
  sourceId: string,
  targetId: string,
): BlobRewrite | RewriteRejection | undefined => {
  const raw = candidate.source[target.path];
  let rewritten: unknown | RewriteRejection | undefined;
  if (target.shape === 'base64') {
    rewritten = rewriteBase64(raw, sourceId, targetId);
  } else if (target.shape === 'object') {
    rewritten = rewriteObject(raw, sourceId, targetId);
  } else if (target.shape === 'nested-json') {
    rewritten = rewriteNestedJson(raw, sourceId, targetId);
  } else {
    rewritten = rewriteJson(raw, sourceId, targetId);
  }
  if (isRejection(rewritten)) {
    return rewritten;
  }
  if (rewritten === undefined) {
    return undefined;
  }
  return { candidate, doc: { [target.path]: rewritten } };
};

/**
 * What one target has to rewrite.
 *
 * The same function backs the dry pass and the real one, so what the operator reads is what gets
 * written: the count of a change is the length of the rewrite list, not an estimate.
 *
 * The scan is consumed page by page. A dashboard manifest carries every widget of the dashboard,
 * so holding every candidate at once would make the peak depend on how much the platform holds
 * rather than on how much the merge rewrites.
 */
const resolveTarget = async (
  handlerContext: UserMergeHandlerContext,
  target: UserMergeBlobTarget,
): Promise<TargetOutcome> => {
  const { context, sourceId, targetId } = handlerContext;
  const outcome = emptyOutcome();
  await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, selectionQuery(target, sourceId), (page) => {
    page.forEach((candidate) => {
      const rewrite = rewriteTarget(candidate, target, sourceId, targetId);
      if (rewrite === 'unparsable') {
        outcome.unparsable += 1;
        return;
      }
      if (rewrite === 'textual') {
        outcome.textual += 1;
        return;
      }
      if (!rewrite) {
        return;
      }
      outcome.rewrites.push(rewrite);
      if (isActive(target, candidate.source)) {
        outcome.active += 1;
      }
    });
  });
  return outcome;
};

/**
 * The draft patch, which no entity type qualifies: `draft_updates_patch` is a global attribute
 * carried by every draftable entity, so the selection is the phrase match alone.
 *
 * A draft is work in progress that stopping the workers does not drain, and validating one after
 * the merge replays its patch against live data. `initial_value` is rewritten with the rest: it
 * is what undoing the draft restores, so leaving it behind would re-inject the source id on a
 * rollback.
 */
const resolveDraftPatch = async (handlerContext: UserMergeHandlerContext): Promise<TargetOutcome> => {
  const { context, sourceId, targetId } = handlerContext;
  const path = USER_MERGE_DRAFT_PATCH_TARGET.path;
  const query = { bool: { must: [{ match_phrase: { [path]: sourceId } }] } };
  const outcome = emptyOutcome();
  await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, query, (page) => {
    page.forEach((candidate) => {
      const rewritten = rewriteJson(candidate.source.draft_change?.draft_updates_patch, sourceId, targetId);
      if (rewritten === 'unparsable') {
        outcome.unparsable += 1;
        return;
      }
      if (rewritten === 'textual') {
        outcome.textual += 1;
        return;
      }
      if (rewritten === undefined) {
        return;
      }
      // Partial document on the object: the sibling `draft_operation` is left as it stands.
      outcome.rewrites.push({ candidate, doc: { draft_change: { draft_updates_patch: rewritten } } });
    });
  });
  return outcome;
};

const alertsFor = (registerRow: string, label: string, path: string, outcome: TargetOutcome): UserMergeRightsAlert[] => {
  const alerts: UserMergeRightsAlert[] = [];
  if (outcome.active > 0) {
    alerts.push({
      register_row_id: registerRow,
      kind: 'rights',
      message: `${outcome.active} ${label}(s) were active while the platform was expected to be at rest`,
    });
  }
  if (outcome.unparsable > 0) {
    alerts.push({
      register_row_id: registerRow,
      kind: 'rights',
      message: `${outcome.unparsable} ${label}(s) hold the source id in a ${path} the platform cannot parse, and were left untouched`,
    });
  }
  if (outcome.textual > 0) {
    alerts.push({
      register_row_id: registerRow,
      kind: 'rights',
      message: `${outcome.textual} ${label}(s) mention the source id inside a ${path} value rather than as one, and were left untouched: review them by hand`,
    });
  }
  return alerts;
};

/**
 * Rewrites the user references held inside the JSON payloads the platform stores as opaque
 * blobs: dashboard manifests, playbook and workflow definitions, form schemas, background task
 * actions, request-access records and draft patches.
 *
 * The selection is by value, not by key. An `internal_id` is a random v4 that nothing in the
 * schema derives, so a value equal to the source id is a reference to the source user whichever
 * key carries it — and none of these payload shapes declares which of its keys accept a User.
 * The comparison is on the whole value, so an id embedded in a longer string is never touched.
 *
 * Three of the four shapes cannot be pre-selected by a query, so the handler reads every
 * document of those types and decides in memory.
 */
export const userMergeBlobsHandler: UserMergeHandler = {
  identifier: USER_MERGE_BLOBS_HANDLER,
  get covers() {
    return userMergeBlobCoveredRows();
  },
  get reads() {
    return userMergeBlobFieldPaths();
  },
  get writes() {
    return userMergeBlobFieldPaths();
  },
  compute: async (handlerContext: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = [];
    const alerts: UserMergeRightsAlert[] = [];
    for (let i = 0; i < USER_MERGE_BLOB_TARGETS.length; i += 1) {
      const target = USER_MERGE_BLOB_TARGETS[i];

      const outcome = await resolveTarget(handlerContext, target);
      changes.push({
        register_row_id: target.registerRow,
        entity_type: target.entityType,
        count: outcome.rewrites.length,
        exact: true,
        detail: target.path,
      });
      // A row this target also answers for is reported at zero of its own: the count above is
      // the whole of what the field holds, and counting it twice would inflate the report.
      (target.alsoCovers ?? []).forEach((row) => {
        changes.push({
          register_row_id: row,
          entity_type: target.entityType,
          count: 0,
          exact: true,
          detail: `covered by ${target.path}, which the register splits on the state of the request rather than on where it is stored`,
        });
      });
      alerts.push(...alertsFor(target.registerRow, target.entityType, target.path, outcome));
    }

    const draftOutcome = await resolveDraftPatch(handlerContext);
    changes.push({
      register_row_id: USER_MERGE_DRAFT_PATCH_TARGET.registerRow,
      entity_type: 'Draftable',
      count: draftOutcome.rewrites.length,
      exact: true,
      detail: USER_MERGE_DRAFT_PATCH_TARGET.path,
    });
    alerts.push(...alertsFor(USER_MERGE_DRAFT_PATCH_TARGET.registerRow, 'draft', USER_MERGE_DRAFT_PATCH_TARGET.path, draftOutcome));

    return { handler: USER_MERGE_BLOBS_HANDLER, changes, alerts };
  },
  apply: async (handlerContext: UserMergeHandlerContext, plan: UserMergeHandlerPlan): Promise<number> => {
    const planned = new Set(plan.changes.filter((change) => change.count > 0).map((change) => change.register_row_id));
    let updated = 0;
    for (let i = 0; i < USER_MERGE_BLOB_TARGETS.length; i += 1) {
      const target = USER_MERGE_BLOB_TARGETS[i];
      if (planned.has(target.registerRow)) {
        const outcome = await resolveTarget(handlerContext, target);
        const updates = outcome.rewrites.map((rewrite) => ({
          id: rewrite.candidate.id,
          index: rewrite.candidate.index,
          doc: rewrite.doc,
        }));

        updated += await userMergeBulkRewrite(handlerContext.context, target.id, updates);
      }
    }
    if (planned.has(USER_MERGE_DRAFT_PATCH_TARGET.registerRow)) {
      const outcome = await resolveDraftPatch(handlerContext);
      const updates = outcome.rewrites.map((rewrite) => ({
        id: rewrite.candidate.id,
        index: rewrite.candidate.index,
        doc: rewrite.doc,
      }));

      updated += await userMergeBulkRewrite(handlerContext.context, USER_MERGE_DRAFT_PATCH_TARGET.id, updates);
    }
    return updated;
  },
};
