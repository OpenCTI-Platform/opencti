import { ENTITY_TYPE_ACTIVITY, ENTITY_TYPE_HISTORY, ENTITY_TYPE_PIR_HISTORY } from '../../schema/internalObject';
import { userMergeBulkRewrite, userMergeBulkUpdate, userMergeScanPagesForRewrite } from './userMerge-bulk';
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
 * The structured parts of the payload, which cannot be pre-selected.
 *
 * `input` and `list_params` map to `flattened` on Elasticsearch and `flat_object` on OpenSearch,
 * `history_changes` maps to `nested`. Nothing in the codebase queries either shape today, and the
 * two engines do not agree on what a term query against them returns, so the handler does not bet
 * on one: it reads the candidates and filters them in memory. A false negative here would silently
 * leave the source id inside an audit record, which is exactly what this row exists to prevent.
 */
const PAYLOAD_FIELDS = ['input', 'list_params', 'history_changes'];

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
      ...PAYLOAD_FIELDS.map((field) => ({ exists: { field: `context_data.${field}` } })),
    ],
  },
});

interface ContextData extends Record<string, unknown> {
  filters?: string;
}

/**
 * The rewritten `context_data` for one record, or null when it holds no reference to the source.
 *
 * The filters string and the structured payloads go through the same remapper as every other
 * serialized user reference, deduplication included: a history entry claiming a field gained the
 * target twice would describe a state the platform cannot hold.
 */
export const userMergeRewriteHistoryPayload = (
  contextData: ContextData,
  sourceId: string,
  targetId: string,
): ContextData | null => {
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
  const filters = contextData[FILTERS_FIELD];
  if (typeof filters === 'string' && filters.includes(sourceId)) {
    // Left alone when it does not parse: an unreadable payload is reported by the caller rather
    // than rewritten by string substitution, which cannot tell a whole value from a substring.
    try {
      const parsed = JSON.parse(filters);
      const result = remapUserInJsonValue(parsed, sourceId, targetId);
      if (result.changed) {
        rewritten[FILTERS_FIELD] = JSON.stringify(result.payload);
        changed = true;
      }
    } catch {
      return null;
    }
  }
  return changed ? rewritten : null;
};

const collectPayloadRewrites = async (
  { context, sourceId, targetId, mergeStartedAt }: UserMergeHandlerContext,
): Promise<{ id: string; index: string; doc: Record<string, unknown> }[]> => {
  const updates: { id: string; index: string; doc: Record<string, unknown> }[] = [];
  await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, payloadQuery(sourceId, mergeStartedAt), (page) => {
    for (let i = 0; i < page.length; i += 1) {
      const candidate = page[i];
      const contextData = (candidate.source as { context_data?: ContextData }).context_data;
      if (contextData) {
        const rewritten = userMergeRewriteHistoryPayload(contextData, sourceId, targetId);
        if (rewritten) {
          updates.push({ id: candidate.id, index: candidate.index, doc: { context_data: rewritten } });
        }
      }
    }
  });
  return updates;
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
    const impacted = new Set((await collectPayloadRewrites(handlerContext)).map((update) => update.id));
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
    const payloadUpdates = await collectPayloadRewrites(handlerContext);
    const payloads = await userMergeBulkRewrite(context, `${USER_MERGE_HISTORY_PAYLOAD_HANDLER}:payload`, payloadUpdates);
    return subjects.updated + payloads;
  },
};
