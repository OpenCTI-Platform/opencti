import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY } from '../../schema/internalObject';
import { DatabaseError } from '../../config/errors';
import { userMergeBulkRewrite, userMergeBulkUpdate, userMergeRefresh, userMergeScanPagesForRewrite } from './userMerge-bulk';
import type { UserMergeHandler, UserMergeHandlerContext, UserMergeHandlerPlan, UserMergePlannedChange, UserMergeRightsAlert } from './userMerge-handler';
import { USER_MERGE_TARGET_INDICES } from './userMerge-handler';
import { remapUserInJsonString, remapUserInJsonValue } from './userMerge-jsonRemap';

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
 * The structured parts of the payload, which cannot be pre-selected.
 *
 * `input` and `list_params` map to `flattened` on Elasticsearch and `flat_object` on OpenSearch.
 * Nothing in the codebase queries that shape today, and the two engines do not agree on what a
 * term query against it returns, so the handler does not bet on one: it reads the candidates and
 * filters them in memory. A false negative here would silently leave the source id inside an audit
 * record, which is exactly what this row exists to prevent.
 */
const FLAT_PAYLOAD_FIELDS = ['input', 'list_params'];

/**
 * The recorded changes, which map to `nested`.
 *
 * A `nested` field is indexed as separate hidden documents, so a plain `exists` on the parent path
 * matches nothing at all — the selection below reaches it through a `nested` query instead. This
 * is the field that carries the author of an attribute change, `creator_id` above all.
 */
const CHANGES_FIELD = 'history_changes';

const PAYLOAD_FIELDS = [...FLAT_PAYLOAD_FIELDS, CHANGES_FIELD];

/** Serialized filter payload. Plain `text`, so a phrase query does reach it. */
const FILTERS_FIELD = 'filters';

const fieldPaths = HISTORY_ENTITY_TYPES.flatMap((entityType) => {
  return [...SUBJECT_ID_FIELDS, ...SUBJECT_IDS_MULTIPLE_FIELDS, ...PAYLOAD_FIELDS, FILTERS_FIELD]
    .map((field) => `${entityType}.context_data.${field}`);
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
 * The candidates for the parts that have to be read back.
 *
 * The phrase query on `filters` is a genuine narrowing; the `exists` clauses are not a search for
 * the source id but a way to skip the records that carry no structured payload at all, which is
 * the bulk of the history index. Both are safe: neither can exclude a document that holds the
 * source id in a field this handler rewrites.
 */
const payloadQuery = (sourceId: string, mergeStartedAt: Date) => ({
  bool: {
    filter: [{ terms: { 'entity_type.keyword': HISTORY_ENTITY_TYPES } }, beforeMergeStarted(mergeStartedAt)],
    minimum_should_match: 1,
    should: [
      { match_phrase: { [`context_data.${FILTERS_FIELD}`]: sourceId } },
      ...FLAT_PAYLOAD_FIELDS.map((field) => ({ exists: { field: `context_data.${field}` } })),
      {
        nested: {
          path: `context_data.${CHANGES_FIELD}`,
          query: { exists: { field: `context_data.${CHANGES_FIELD}.field` } },
        },
      },
    ],
  },
});

interface ContextData extends Record<string, unknown> {
  filters?: string;
}

const isRecord = (value: unknown): value is Record<string, unknown> => {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
};

/** The two sides of a recorded change, both holding the same `{ raw, translated }` pairs. */
const CHANGE_VALUE_FIELDS = ['changes_added', 'changes_removed'];

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

export interface HistoryPayloadRewrite {
  /** The rewritten `context_data`, or null when nothing in it could be rewritten. */
  rewritten: ContextData | null;
  /**
   * The serialized filters name the source but do not parse, and were left untouched.
   *
   * Independent of `rewritten`: a record can have its structured payload rewritten and still carry
   * a filters string that could not be, and that one must not be lost with the rest.
   */
  unparsable: boolean;
}

/**
 * The rewritten `context_data` for one record, and whether part of it had to be left alone.
 *
 * The filters string and the structured payloads go through the same remapper as every other
 * serialized user reference, deduplication included: a history entry claiming a field gained the
 * target twice would describe a state the platform cannot hold.
 */
export const userMergeRewriteHistoryPayload = (
  contextData: ContextData,
  sourceId: string,
  targetId: string,
): HistoryPayloadRewrite => {
  const rewritten: ContextData = { ...contextData };
  let changed = false;
  for (let i = 0; i < PAYLOAD_FIELDS.length; i += 1) {
    const field = PAYLOAD_FIELDS[i];
    const value = contextData[field];
    if (value !== undefined && value !== null) {
      const result = remapUserInJsonValue(value, sourceId, targetId);
      if (result.changed) {
        rewritten[field] = result.payload;
        changed = true;
      }
    }
  }
  const changeLabels = rewriteChangeLabels(rewritten[CHANGES_FIELD], sourceId, targetId);
  if (changeLabels.changed) {
    rewritten[CHANGES_FIELD] = changeLabels.value;
    changed = true;
  }
  // Left alone when it does not parse: an unreadable payload is reported rather than rewritten by
  // string substitution, which cannot tell a whole value from a substring. The fields rewritten
  // above are kept, so the record is not lost with it.
  let unparsable = false;
  const filters = contextData[FILTERS_FIELD];
  if (typeof filters === 'string') {
    const result = remapUserInJsonString(filters, sourceId, targetId);
    if (result.changed) {
      rewritten[FILTERS_FIELD] = result.json;
      changed = true;
    } else if (!result.parsed) {
      unparsable = true;
    }
  }
  return { rewritten: changed ? rewritten : null, unparsable };
};

type PayloadUpdate = { id: string; index: string; doc: Record<string, unknown> };

/**
 * Walks the records whose payload names the source and hands the rewrites over one page at a
 * time, keeping none of them past their page.
 *
 * How many records name a user has no bound the merge controls, and each rewrite carries a whole
 * `context_data` — the changes of a bulk edit, the raw input, the filters. Collected over the
 * whole scan, they would make the peak memory, and the size of a single bulk request, grow with
 * the history of the user rather than with a page. Returns the count of records whose filters
 * name the source but could not be read, rewritten or not for the rest.
 */
const scanPayloadRewrites = async (
  { context, sourceId, targetId, mergeStartedAt }: UserMergeHandlerContext,
  onPage: (updates: PayloadUpdate[]) => Promise<void> | void,
): Promise<number> => {
  let unparsable = 0;
  await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, payloadQuery(sourceId, mergeStartedAt), async (page) => {
    const updates: PayloadUpdate[] = [];
    for (let i = 0; i < page.length; i += 1) {
      const candidate = page[i];
      const contextData = (candidate.source as { context_data?: ContextData }).context_data;
      if (contextData) {
        const result = userMergeRewriteHistoryPayload(contextData, sourceId, targetId);
        if (result.unparsable) {
          unparsable += 1;
        }
        if (result.rewritten) {
          updates.push({ id: candidate.id, index: candidate.index, doc: { context_data: result.rewritten } });
        }
      }
    }
    await onPage(updates);
  });
  return unparsable;
};

/**
 * Rewrites the user references buried in a recorded action.
 *
 * Split from the history handler of the previous chunk on purpose: that one moves attribution
 * fields, which are plain keywords a script can rewrite in place. This one deals with the payload
 * the action carried, which is stored in three shapes that no single query reaches.
 */
export const userMergeHistoryPayloadHandler: UserMergeHandler = {
  identifier: USER_MERGE_HISTORY_PAYLOAD_HANDLER,
  covers: [REGISTER_ROW],
  reads: fieldPaths,
  writes: fieldPaths,
  compute: async (handlerContext: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const { context, sourceId, mergeStartedAt } = handlerContext;
    // Both selections are collapsed into one set of document ids rather than added up, so that a
    // record naming the source in its subject and in its payload is reported once.
    const impacted = new Set<string>();
    const unparsable = await scanPayloadRewrites(handlerContext, (updates) => {
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
      detail: `records written before ${mergeStartedAt.toISOString()} naming the source in their subject or payload; what the merge on this pair wrote about the source is out of reach by construction`,
    }];
    // Not blocking, like the unreadable payloads of the other handlers: the record is left as it
    // stands and the operator decides. Without this, the filters of an audit record would keep
    // naming the source and nothing would say so.
    const alerts: UserMergeRightsAlert[] = [];
    if (unparsable > 0) {
      alerts.push({
        register_row_id: REGISTER_ROW,
        kind: 'rights',
        message: `${unparsable} ${ENTITY_TYPE_HISTORY} record(s) hold the source id in a ${FILTERS_FIELD} the platform cannot parse, and were left untouched`,
      });
    }
    return { handler: USER_MERGE_HISTORY_PAYLOAD_HANDLER, changes, alerts };
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
    const label = `${USER_MERGE_HISTORY_PAYLOAD_HANDLER}:payload`;
    const written = new Set<string>();
    let payloads = 0;
    try {
      await scanPayloadRewrites(handlerContext, async (updates) => {
        payloads += await userMergeBulkRewrite(context, label, updates, { refresh: false });
        updates.forEach((update) => written.add(update.index));
      });
    } catch (err) {
      // A bulk is no more atomic than the update above: the pages already written stay written,
      // and a run reporting zero would read as "nothing was touched". Re-running completes it.
      throw DatabaseError('User merge history payload rewrite aborted', { label, updated: subjects.updated + payloads, cause: err });
    }
    await userMergeRefresh(label, Array.from(written));
    return subjects.updated + payloads;
  },
};
