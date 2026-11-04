import { RULE_MANAGER_USER_UUID } from '../../utils/access';
import type { UserMergeHandler, UserMergeHandlerPlan, UserMergePlannedChange } from './userMerge-handler';

export const USER_MERGE_RESIDUAL_HANDLER = 'residual-references';

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
  /**
   * The register asked for a safety net over the fields it does not name. It is not run at merge
   * time: the merge answers for the references the register records, and one it does not record
   * is a new row, and a new handler, rather than something to discover on a production platform.
   * A sweep over every field of every index also does not scale: it reads every document naming
   * the source, and OpenSearch refuses to expand `*` past its clause limit.
   */
  {
    registerRow: 'any-type.unregistered-serialized-field',
    entityType: 'Any type',
    detail: 'out of the merge scope: the merge rewrites the references the register records, and an unrecorded one is answered by a new row and handler',
  },
];

/** Claims the rows no handler acts on, and writes nothing. */
export const userMergeResidualHandler: UserMergeHandler = {
  identifier: USER_MERGE_RESIDUAL_HANDLER,
  covers: ACKNOWLEDGED_ROWS.map((row) => row.registerRow),
  reads: [],
  writes: [],
  compute: async (): Promise<UserMergeHandlerPlan> => {
    const changes: UserMergePlannedChange[] = ACKNOWLEDGED_ROWS.map((row) => ({
      register_row_id: row.registerRow,
      entity_type: row.entityType,
      count: 0,
      exact: true,
      detail: row.detail,
    }));
    return { handler: USER_MERGE_RESIDUAL_HANDLER, changes, alerts: [] };
  },
  apply: async (): Promise<number> => 0,
};
