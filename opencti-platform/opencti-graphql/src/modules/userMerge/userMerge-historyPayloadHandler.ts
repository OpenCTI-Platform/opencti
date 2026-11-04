import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY } from '../../schema/internalObject';
import { DatabaseError } from '../../config/errors';
import { userMergeBulkRewrite, userMergeBulkUpdate, userMergeRefresh, userMergeScanPagesForRewrite } from './userMerge-bulk';
import type { UserMergeHandler, UserMergeHandlerContext, UserMergeHandlerPlan, UserMergePlannedChange } from './userMerge-handler';
import { USER_MERGE_TARGET_INDICES } from './userMerge-handler';
import { remapUserInJsonValue } from './userMerge-jsonRemap';

export const USER_MERGE_HISTORY_PAYLOAD_HANDLER = 'history-context-data-payload';

const HISTORY_ENTITY_TYPES = [ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY];

const REGISTER_ROW = 'history.context-data-payload';

/**
 * The subject of a recorded action, when that subject is an account.
 *
 * All of them are declared `format: 'short'`, so they map to plain keywords and the scalar
 * discovery — which only looks at `format: 'id'` — never sees them. They are exact-match
 * selectable and rewritten by script, without reading the documents back.
 *
 * `created_by_id` and `created_by_ref_id` are deliberately absent: they hold the STIX createdBy
 * reference, which points at an Identity and never at a User internal id.
 */
const SUBJECT_ID_FIELDS = ['id', 'element_id', 'entity_id', 'from_id', 'to_id'];
const SUBJECT_IDS_MULTIPLE_FIELDS = ['selected_ids'];

/**
 * The recorded changes, which map to `nested`.
 *
 * They are what the history of an entity displays, and the platform resolves the ids they hold
 * into names when it reads them back (`attributesChangesResolver`), rebuilding the message from
 * them on the way. Once the source account is deleted, a change naming it would read "Restricted".
 *
 * The rest of the payload — `input`, `list_params`, `filters` — is retained, under a row of its
 * own: the API does not expose it and nothing resolves it, so a merge would rewrite an audit
 * record for a reader that does not exist.
 */
const CHANGES_FIELD = 'history_changes';

/** The two sides of a recorded change, both holding the same `{ raw, translated }` pairs. */
const CHANGE_VALUE_FIELDS = ['changes_added', 'changes_removed'];

const fieldPaths = HISTORY_ENTITY_TYPES.flatMap((entityType) => {
  return [...SUBJECT_ID_FIELDS, ...SUBJECT_IDS_MULTIPLE_FIELDS, CHANGES_FIELD].map((field) => `${entityType}.context_data.${field}`);
});

/**
 * Everything the merge itself wrote is out of reach.
 *
 * The source disablement and the "A merged into B" record both name the source by construction.
 * Cutting on the first merge of the pair covers them without naming them — including the ones a
 * later change may add — and makes a replay a no-op rather than a second erasure.
 *
 * The boundary belongs to the pair, not to the run. Cut at the current run instead and every
 * later dry-run, the deletion gate's included, would count the previous merge's own traces as
 * references still pending.
 */
const beforeMergeStarted = (mergeStartedAt: Date) => ({ range: { timestamp: { lt: mergeStartedAt.toISOString() } } });

const subjectIdQuery = (sourceId: string, mergeStartedAt: Date) => ({
  bool: {
    filter: [{ terms: { 'entity_type.keyword': HISTORY_ENTITY_TYPES } }, beforeMergeStarted(mergeStartedAt)],
    minimum_should_match: 1,
    should: [...SUBJECT_ID_FIELDS, ...SUBJECT_IDS_MULTIPLE_FIELDS].map((field) => ({
      term: { [`context_data.${field}.keyword`]: sourceId },
    })),
  },
});

/**
 * The records whose recorded changes name the source.
 *
 * Every value of a change maps to `text`, so a phrase query on the id is a genuine narrowing: the
 * standard analyzer splits it on its dashes, wherever it sits — a plain `raw` id, an id inside a
 * serialized `raw` object, a key of the `translated` label map. It is a pre-selection, confirmed
 * value by value once read, and it keeps the scan to the records that name the source rather than
 * every record that carries a change.
 */
const changesQuery = (sourceId: string, mergeStartedAt: Date) => ({
  bool: {
    filter: [
      { terms: { 'entity_type.keyword': HISTORY_ENTITY_TYPES } },
      beforeMergeStarted(mergeStartedAt),
      {
        nested: {
          path: `context_data.${CHANGES_FIELD}`,
          query: {
            bool: {
              minimum_should_match: 1,
              should: CHANGE_VALUE_FIELDS.flatMap((side) => ['raw', 'translated'].map((part) => ({
                match_phrase: { [`context_data.${CHANGES_FIELD}.${side}.${part}`]: sourceId },
              }))),
            },
          },
        },
      },
    ],
  },
});

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

/**
 * The label map a recorded change stores next to the id it resolved, serialized as
 * `{"<id>":"<representative name>"}`.
 *
 * The id sits in key position, and the shared remapper rewrites values only — a deliberate choice,
 * since it walks opaque blobs where no key position is known. Here the shape is declared by the
 * schema, so the key is rewritten at this level rather than by loosening the remapper everywhere.
 *
 * Only the id moves. The name is left as recorded, like every other label the merge crosses.
 *
 * Returns null when there is nothing to do, including when the payload does not parse: an
 * unreadable map is left alone rather than patched by string substitution.
 */
const rewriteTranslatedIds = (serialized: string, sourceId: string, targetId: string): string | null => {
  if (!serialized.includes(sourceId)) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) {
    return null;
  }
  const entries = Object.entries(parsed);
  if (!entries.some(([key]) => key === sourceId)) {
    return null;
  }
  // A map naming both users keeps the entry already held for the target: the merge cannot leave it
  // naming the same account twice, and the target's own label is the one that still resolves.
  const holdsTarget = entries.some(([key]) => key === targetId);
  const rewritten: Record<string, unknown> = {};
  entries.forEach(([key, value]) => {
    if (key === sourceId) {
      if (!holdsTarget) {
        rewritten[targetId] = value;
      }
      return;
    }
    rewritten[key] = value;
  });
  return JSON.stringify(rewritten);
};

/**
 * Walks the recorded changes and rewrites the label maps they carry.
 *
 * Runs after the shared remapper, which has already moved the ids held in value position — `raw`
 * among them. This pass only reaches what that one cannot see.
 */
const rewriteChangeLabels = (changes: unknown, sourceId: string, targetId: string): { value: unknown; changed: boolean } => {
  if (!Array.isArray(changes)) {
    return { value: changes, changed: false };
  }
  let changed = false;
  const rewritten = changes.map((change) => {
    if (!isRecord(change)) {
      return change;
    }
    const entry: Record<string, unknown> = { ...change };
    CHANGE_VALUE_FIELDS.forEach((field) => {
      const values = entry[field];
      if (!Array.isArray(values)) {
        return;
      }
      entry[field] = values.map((value) => {
        if (!isRecord(value) || typeof value.translated !== 'string') {
          return value;
        }
        const translated = rewriteTranslatedIds(value.translated, sourceId, targetId);
        if (translated === null) {
          return value;
        }
        changed = true;
        return { ...value, translated };
      });
    });
    return entry;
  });
  return { value: changed ? rewritten : changes, changed };
};

/**
 * The rewritten recorded changes of one record, or null when they name nobody relevant.
 *
 * The values go through the same remapper as every other serialized user reference, deduplication
 * included: a history entry claiming a field gained the target twice would describe a state the
 * platform cannot hold.
 */
export const userMergeRewriteHistoryChanges = (changes: unknown, sourceId: string, targetId: string): unknown[] | null => {
  if (!Array.isArray(changes)) {
    return null;
  }
  const values = remapUserInJsonValue(changes, sourceId, targetId);
  const labels = rewriteChangeLabels(values.payload, sourceId, targetId);
  return values.changed || labels.changed ? labels.value as unknown[] : null;
};

type ChangesUpdate = { id: string; index: string; doc: Record<string, unknown> };

/**
 * Walks the records whose changes name the source and hands the rewrites over one page at a time,
 * keeping none of them past their page: a bulk edit records every element it touched, so the size
 * of a rewrite is not bounded by the merge.
 */
const scanChangesRewrites = async (
  { context, sourceId, targetId, mergeStartedAt }: UserMergeHandlerContext,
  onPage: (updates: ChangesUpdate[]) => Promise<void> | void,
): Promise<void> => {
  await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, changesQuery(sourceId, mergeStartedAt), async (page) => {
    const updates: ChangesUpdate[] = [];
    for (let i = 0; i < page.length; i += 1) {
      const candidate = page[i];
      const changes = (candidate.source as { context_data?: Record<string, unknown> }).context_data?.[CHANGES_FIELD];
      const rewritten = userMergeRewriteHistoryChanges(changes, sourceId, targetId);
      if (rewritten) {
        // Partial document: only the changes move, the rest of the record is left as recorded.
        updates.push({ id: candidate.id, index: candidate.index, doc: { context_data: { [CHANGES_FIELD]: rewritten } } });
      }
    }
    await onPage(updates);
  });
};

/**
 * Rewrites the user references a recorded action carries in what the platform shows of it: its
 * subject and its recorded changes.
 *
 * Split from the history handler of the previous chunk on purpose: that one moves attribution
 * fields, which are plain keywords a script can rewrite in place. The recorded changes are
 * `nested` values that have to be read back and walked.
 */
export const userMergeHistoryPayloadHandler: UserMergeHandler = {
  identifier: USER_MERGE_HISTORY_PAYLOAD_HANDLER,
  covers: [REGISTER_ROW],
  reads: fieldPaths,
  writes: fieldPaths,
  compute: async (handlerContext: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const { context, sourceId, mergeStartedAt } = handlerContext;
    // Both selections are collapsed into one set of document ids rather than added up, so that a
    // record naming the source in its subject and in its changes is reported once.
    const impacted = new Set<string>();
    await scanChangesRewrites(handlerContext, (updates) => {
      updates.forEach((update) => impacted.add(update.id));
    });
    await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, subjectIdQuery(sourceId, mergeStartedAt), (page) => {
      for (let i = 0; i < page.length; i += 1) {
        impacted.add(page[i].id);
      }
    });
    const changes: UserMergePlannedChange[] = [{
      register_row_id: REGISTER_ROW,
      entity_type: ENTITY_TYPE_HISTORY,
      count: impacted.size,
      exact: true,
      detail: `records written before ${mergeStartedAt.toISOString()} naming the source in their subject or recorded changes; what the merge on this pair wrote about the source is out of reach by construction`,
    }];
    return { handler: USER_MERGE_HISTORY_PAYLOAD_HANDLER, changes, alerts: [] };
  },
  apply: async (handlerContext: UserMergeHandlerContext): Promise<number> => {
    const { context, sourceId, targetId, mergeStartedAt } = handlerContext;
    const singleRewrites = SUBJECT_ID_FIELDS
      .map((field) => `if (params.source.equals(ctx._source.context_data.${field})) { ctx._source.context_data.${field} = params.target; }`)
      .join(' ');
    const multipleRewrites = SUBJECT_IDS_MULTIPLE_FIELDS
      .map((field) => `if (ctx._source.context_data.${field} instanceof List) { def v = ctx._source.context_data.${field}; if (v.contains(params.source)) { v.removeIf(i -> params.source.equals(i)); if (!v.contains(params.target)) { v.add(params.target); } } }`)
      .join(' ');
    const subjects = await userMergeBulkUpdate(
      `${USER_MERGE_HISTORY_PAYLOAD_HANDLER}:subject-ids`,
      USER_MERGE_TARGET_INDICES,
      {
        query: subjectIdQuery(sourceId, mergeStartedAt),
        script: {
          source: `if (ctx._source.context_data != null) { ${singleRewrites} ${multipleRewrites} }`,
          params: { source: sourceId, target: targetId },
        },
      },
    );
    // Written as the scan goes, which is safe: the scan pages on `internal_id` and `_index`, which
    // the rewrite leaves alone, and a page already written lies behind the cursor. The pages are
    // left unrefreshed and the indices written refreshed once, rather than once per page on the
    // heaviest index of the platform.
    const label = `${USER_MERGE_HISTORY_PAYLOAD_HANDLER}:changes`;
    const written = new Set<string>();
    let rewritten = 0;
    try {
      await scanChangesRewrites(handlerContext, async (updates) => {
        rewritten += await userMergeBulkRewrite(context, label, updates, { refresh: false });
        updates.forEach((update) => written.add(update.index));
      });
    } catch (err) {
      // A bulk is no more atomic than the update above: the pages already written stay written,
      // and a run reporting zero would read as "nothing was touched". Re-running completes it.
      throw DatabaseError('User merge history changes rewrite aborted', { label, updated: subjects.updated + rewritten, cause: err });
    }
    await userMergeRefresh(label, Array.from(written));
    return subjects.updated + rewritten;
  },
};
