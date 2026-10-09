import { logApp } from '../../../config/conf';
import { updateAttribute } from '../../../database/middleware';
import { fullEntitiesList } from '../../../database/middleware-loader';
import { FilterMode, StatusScope } from '../../../generated/graphql';
import { ENTITY_TYPE_STATUS } from '../../../schema/internalObject';
import type { BasicStoreEntity, BasicWorkflowStatus } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { bypassDraftContext } from '../../../utils/draftContext';

// Duplicated from workflow-domain.ts rather than imported, to keep this a true leaf module
// (no import chain back to workflow-domain.ts / middleware.ts / schema).
const bypassDraftUser = (user: AuthUser): AuthUser => ({ ...user, draft_context: undefined });

/**
 * Maps a `WorkflowInstance.scope` value onto the `StatusScope` used for the Status mapping key.
 * `'standard'` is the default scope stamped by `initializeWorkflowInstance` when no explicit
 * status was supplied at creation, and maps onto `StatusScope.Global` (the only scope reconciled
 * by the status mapping today).
 */
export const resolveProjectionScope = (scope: string | undefined): StatusScope => (
  (scope && scope !== 'standard' ? scope as StatusScope : StatusScope.Global)
);

/**
 * Resolves the `Status` id mapped to (entity type, scope, state), or `null` if none matches.
 * Takes an explicit `user` rather than deriving one from `context.user` — some callers (e.g.
 * entity creation triggered by the sync manager) build a context with no `.user` set and thread
 * the identity separately, so relying on `context.user!` would throw for them.
 */
export const resolveMappedStatusId = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope,
  stateId: string,
): Promise<string | null> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const matchingStatuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [entityType] },
        { key: ['scope'], values: [scope] },
        { key: ['template_id'], values: [stateId] },
      ],
      filterGroups: [],
    },
  });
  return matchingStatuses[0]?.id ?? null;
};

/**
 * Projects a workflow state onto the legacy `x_opencti_workflow_id` field of an entity, by
 * resolving the `Status` mapped to (entity type, scope, state) and writing its id. `scope` is an
 * explicit parameter — callers already have it on hand (from the `WorkflowInstance` they're
 * acting on) and must never re-derive it ad hoc, since the mapping key includes scope. `user` is
 * likewise explicit rather than derived from `context.user!` — see `resolveMappedStatusId`.
 *
 * A missing mapping (e.g. transient eventual-consistency window right after publish) is logged
 * and skipped rather than thrown — this is a projection best-effort write, not a hard invariant
 * check; callers (sync/async transition paths, read-repair) must not fail on it.
 */
export const projectWorkflowState = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { id?: string; internal_id?: string; entity_type: string },
  stateId: string,
  scope: StatusScope,
): Promise<void> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const entityType = entity.entity_type;
  const entityId = entity.internal_id || entity.id;

  try {
    const statusId = await resolveMappedStatusId(executionContext, executionUser, entityType, scope, stateId);
    if (!statusId) {
      logApp.warn('[OPENCTI-MODULE] No Status mapped for workflow state, skipping projection', { entityType, scope, stateId });
      return;
    }

    await updateAttribute(executionContext, executionUser, entityId, entityType, [
      { key: 'x_opencti_workflow_id', value: [statusId] },
    ]);
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Failed to project workflow state onto entity', { cause: error, entityType, scope, stateId, entityId });
  }
};
