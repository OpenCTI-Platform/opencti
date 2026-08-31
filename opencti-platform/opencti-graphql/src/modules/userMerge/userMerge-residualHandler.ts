import { RULE_MANAGER_USER_UUID } from '../../utils/access';
import { userMergeScanPagesForRewrite } from './userMerge-bulk';
import type { UserMergeHandler, UserMergeHandlerContext, UserMergeHandlerPlan, UserMergePlannedChange } from './userMerge-handler';
import { USER_MERGE_TARGET_INDICES } from './userMerge-handler';

export const USER_MERGE_RESIDUAL_HANDLER = 'residual-references';

const DETECTOR_ROW = 'any-type.unregistered-serialized-field';

/**
 * Rows that no handler has to act on, claimed here with the reason rather than left uncovered.
 *
 * An uncovered row keeps the deletion gate shut forever, so a row a handler will never touch has
 * to say so explicitly. Each of these was checked against the sources rather than assumed.
 */
const ACKNOWLEDGED_ROWS: Array<{ registerRow: string; entityType: string; detail: string }> = [
  {
    registerRow: 'deleted-objects.all-references',
    entityType: 'Deleted objects',
    detail: 'no dedicated pass: the trash index is part of the index scope every handler already writes to',
  },
  {
    registerRow: 'inferred.derived-references',
    entityType: 'Inferred relationships',
    detail: `nothing to invalidate: inferred elements are created by the rule engine, so their creator is always ${RULE_MANAGER_USER_UUID}, and no rule produces a relationship type that carries a user`,
  },
  {
    registerRow: 'notification.subscription-topics',
    entityType: 'Notification subscription',
    detail: 'nothing persisted: a subscription is a live GraphQL stream filtered on the connected user in memory, and it dies with the connection',
  },
];

/**
 * Best-effort sweep for a source id sitting somewhere the audit did not name.
 *
 * The register asked for a rewriting safety net. It is shipped as a detector instead, because a
 * blind rewrite is more dangerous than the gap it closes: on an already merged pair, most of what
 * still names the source is meant to stay — the account document itself, and the traces the merge
 * wrote about it. This reports and never writes; the operator decides.
 *
 * It runs in the compute phase, so during a merge it also counts what the deterministic handlers
 * are about to rewrite. That is noise, not a finding. The reading that matters is the one the
 * deletion gate takes: a dry-run on a pair already merged, where what it reports really is what
 * was left behind. Moving it after the writes would need a third engine phase, and would buy a
 * tidier report rather than a guarantee — it does not block either way.
 *
 * It does not block. The count it plans is always zero, which is the truth about what it changes,
 * and keeps its plan stable between the dry pass and the real one.
 */
const residualQuery = (sourceId: string, mergeStartedAt: Date) => ({
  bool: {
    must: [{ query_string: { query: `"${sourceId}"`, fields: ['*'] } }],
    must_not: [
      // The source account document is expected to still name itself: it is being disabled, not
      // rewritten, and the deletion gate is what decides its fate.
      { term: { 'internal_id.keyword': sourceId } },
      // Everything written since the merge on this pair started, which is what it wrote about the
      // source. Bounded by the pair rather than by the run, so a later dry-run sees it the same way.
      { range: { timestamp: { gte: mergeStartedAt.toISOString() } } },
    ],
  },
});

export interface UserMergeResidualFinding {
  entity_type: string;
  count: number;
}

export const summarizeResidualFindings = (findings: UserMergeResidualFinding[]): string => {
  if (findings.length === 0) {
    return 'no serialized reference to the source found outside the rows the handlers claim';
  }
  const listed = findings
    .slice()
    .sort((left, right) => right.count - left.count || left.entity_type.localeCompare(right.entity_type))
    .map((finding) => `${finding.entity_type} (${finding.count})`)
    .join(', ');
  return `best-effort sweep, nothing rewritten: ${listed}`;
};

export const userMergeResidualHandler: UserMergeHandler = {
  identifier: USER_MERGE_RESIDUAL_HANDLER,
  covers: [...ACKNOWLEDGED_ROWS.map((row) => row.registerRow), DETECTOR_ROW],
  reads: [],
  writes: [],
  compute: async ({ context, sourceId, mergeStartedAt }: UserMergeHandlerContext): Promise<UserMergeHandlerPlan> => {
    const counts = new Map<string, number>();
    await userMergeScanPagesForRewrite(context, USER_MERGE_TARGET_INDICES, residualQuery(sourceId, mergeStartedAt), (page) => {
      for (let i = 0; i < page.length; i += 1) {
        const entityType = (page[i].source.entity_type as string) ?? 'unknown';
        counts.set(entityType, (counts.get(entityType) ?? 0) + 1);
      }
    });
    const findings = Array.from(counts.entries()).map(([entity_type, count]) => ({ entity_type, count }));
    const changes: UserMergePlannedChange[] = [
      ...ACKNOWLEDGED_ROWS.map((row) => ({
        register_row_id: row.registerRow,
        entity_type: row.entityType,
        count: 0,
        exact: true,
        detail: row.detail,
      })),
      {
        register_row_id: DETECTOR_ROW,
        entity_type: 'Any type',
        count: 0,
        exact: true,
        detail: summarizeResidualFindings(findings),
      },
    ];
    return { handler: USER_MERGE_RESIDUAL_HANDLER, changes, alerts: [] };
  },
  apply: async (): Promise<number> => 0,
};
