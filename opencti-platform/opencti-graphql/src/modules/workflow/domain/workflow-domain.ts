import { randomUUID } from 'node:crypto';
import { LRUCache } from 'lru-cache';
import { Promise as BluePromise } from 'bluebird';
import conf, { booleanConf, logApp, ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled } from '../../../config/conf';
import { ForbiddenAccess, FunctionalError } from '../../../config/errors';
import { getEntitiesListFromCache } from '../../../database/cache';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { loadAssignees, loadParticipants } from '../../../database/members';
import { createEntity, createRelation, deleteElementById, idVocabulary, loadEntity, updateAttribute } from '../../../database/middleware';
import { fullEntitiesList, internalLoadById, storeLoadById, storeLoadByIds } from '../../../database/middleware-loader';
import { READ_DATA_INDICES, READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY } from '../../../database/utils';
import { elAggregationCount, ES_MAX_CONCURRENCY } from '../../../database/engine';
import { createListTask } from '../../../domain/backgroundTask-common';
import { resolveUserById } from '../../user/user-domain';
import { createStatus, findByType as findStatusesByType } from '../../../domain/status';
import { checkEnterpriseEdition } from '../../../enterprise-edition/ee';
import { type EditInput, FilterMode, FilterOperator, StatusScope, OrderingMode, VocabularyCategory } from '../../../generated/graphql';
import { type BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY } from '../../vocabulary/vocabulary-types';
import { lockResources } from '../../../lock/master-lock';
import { addWorkflowPublishCount, addWorkflowRequestAccessMigrationCount, addWorkflowRequestAccessPublishCount } from '../../../manager/telemetryManager';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../schema/internalObject';
import { RELATION_HAS_WORKFLOW } from '../../../schema/internalRelationship';
import { schemaAttributesDefinition } from '../../../schema/schema-attributes';
import { X_CLOSING_REASON } from '../../../schema/identifier';
import type { BasicStoreCommon, BasicStoreEntity, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import {
  AccessOperation,
  KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS,
  SYSTEM_USER,
  WORKFLOW_MANAGER_USER,
  isBypassUser,
  isInternalUser,
  isUserHasCapability,
  validateUserAccessOperation,
} from '../../../utils/access';
import { bypassDraftContext, getDraftContext } from '../../../utils/draftContext';
import { now } from '../../../utils/format';
import { controlUserConfidenceAgainstElement } from '../../../utils/confidence-level';
import { addFilter } from '../../../utils/filtering/filtering-utils';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_UPDATE_LINKED } from '../../draftWorkspace/draftOperations';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../draftWorkspace/draftWorkspace-types';
import { type BasicStoreEntityCaseRfi, ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../case/case-rfi/case-rfi-types';
import { findByType as findEntitySettingByType } from '../../entitySetting/entitySetting-domain';
import { validateSetting } from '../../entitySetting/entitySetting-validators';
import type { BasicStoreEntityEntitySetting } from '../../entitySetting/entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../entitySetting/entitySetting-types';
import { addNotification } from '../../notification/notification-domain';
import type { NotificationAddInput } from '../../notification/notification-types';
import { WorkflowFactory } from '../engine/workflow-factory';
import type { WorkflowSchema } from '../engine/workflow-schema';
import {
  type AsyncActionSlot,
  COMMENT_MAX_LENGTH,
  ENTITY_TYPE_WORKFLOW_DEFINITION,
  ENTITY_TYPE_WORKFLOW_INSTANCE,
  type TriggerResult,
  type WorkflowActionConfig,
  type WorkflowDefinitionData,
  type WorkflowPendingTransition,
  type WorkflowSerializedState,
  type WorkflowSerializedTransition,
  type WorkflowValidationError,
} from '../types/workflow-types';
import { extractCanonicalStateIds, findInstancesBlockingStateRemoval, validateWorkflowDefinitionData } from '../workflow-validation';
import { computeStateOrder, findStatesWithOutgoingTransitions } from './workflow-ordering';
import { findInstancesInStates, isStatusReferencedByEntity } from './workflow-status-usage';
import { projectWorkflowState, resolveMappedStatusId, resolveProjectionScope } from './workflow-projection';
import { appendWorkflowHistoryEntry, closingReasonNotWrittenError, isClosingReasonLost, runWorkflowBypassActions } from './workflow-async-completion';
import {
  type ConvertStatusToDefinitionResult,
  convertStatusToDefinition,
  getPublishBlockingDiagnostics,
  pickMigrationScope,
  tryConvertRequestAccessGroup,
  type WorkflowMigrationConversionResult,
} from '../migration/status-to-definition-converter';
import { assertCanEnterRequestAccessOutcome, findStateOutcome, mirrorRequestAccessStatus, recordRequestAccessDecision, type RequestAccessOutcome } from './workflow-request-access';

// EE-only action types – conditions on transitions and onEnter/onExit state actions.
// 'validateDraft' is a CE feature and must NOT be listed here.
const EE_ONLY_ACTION_TYPES = new Set<WorkflowActionConfig['type']>([
  'updateAuthorizedMembers',
  'shareWithOrganizations',
  'unshareFromOrganizations',
  'asyncBulkAction',
  'shareRequestedEntities',
]);
const hasEEActions = (actions?: WorkflowActionConfig[]) => (actions ?? []).some((a) => EE_ONLY_ACTION_TYPES.has(a.type));
const hasConditions = (conditions?: WorkflowSerializedTransition['conditions']) => Array.isArray(conditions?.filters) && conditions.filters.length > 0;

// `AuthContext.user` is NOT reliably populated (e.g. during platform bootstrap/init flows,
// contexts are built without a `.user`, with the actual user passed as a separate function
// argument instead). Always derive the execution user from the explicit `user` parameter,
// mirroring the draft_context stripping that bypassDraftContext applies to the context itself.
const bypassDraftUser = (user: AuthUser): AuthUser => ({ ...user, draft_context: undefined });

// Domain-specific types
interface WorkflowVersion {
  id: string;
  timestamp: string;
  createdBy: string;
  content: string;
  validation_errors: WorkflowValidationError[];
}

interface WorkflowDefinitionEntity extends BasicStoreEntity {
  name: string;
  published_version?: WorkflowVersion;
  draft_version?: WorkflowVersion;
  all_versions: WorkflowVersion[];
}

export interface WorkflowDefinitionResponse extends WorkflowSchema {
  published: boolean;
}

export interface EntitySettingWithWorkflowResponse {
  errors: WorkflowValidationError[];
  published: boolean;
  id: string;
  workflow_id?: string | null;
  target_type: string;
}

/**
 * Validate workflow version consistency.
 * Ensures that draft_version and published_version are present in all_versions.
 */
const validateVersionConsistency = (workflowEntity: WorkflowDefinitionEntity): void => {
  const { draft_version, published_version, all_versions } = workflowEntity;

  if (!all_versions || !Array.isArray(all_versions)) {
    throw FunctionalError('all_versions must be an array');
  }

  // Check draft_version is in all_versions
  if (draft_version) {
    const draftInHistory = all_versions.some((v) => v.id === draft_version.id);
    if (!draftInHistory) {
      throw FunctionalError('Consistency error: draft_version not found in all_versions', {
        draftVersionId: draft_version.id,
      });
    }
  }

  // Check published_version is in all_versions
  if (published_version) {
    const publishedInHistory = all_versions.some((v) => v.id === published_version.id);
    if (!publishedInHistory) {
      throw FunctionalError('Consistency error: published_version not found in all_versions', {
        publishedVersionId: published_version.id,
      });
    }
  }
};

/**
 * Sends a UI notification to all assignees and participants of the entity
 * (excluding the user who triggered the transition) when a comment is provided.
 */
const notifyWorkflowTransitionComment = async (
  context: AuthContext,
  entity: BasicStoreEntity,
  eventName: string,
  comment: string,
  triggeredByUserId: string,
): Promise<void> => {
  try {
    const [assignees, participants] = await Promise.all([
      loadAssignees(context, SYSTEM_USER, entity),
      loadParticipants(context, SYSTEM_USER, entity),
    ]);

    const seenIds = new Set<string>();
    const uniqueRecipients = [...assignees, ...participants].filter((recipient) => {
      const recipientId = recipient.id;
      if (!recipientId || seenIds.has(recipientId) || recipientId === triggeredByUserId) return false;
      seenIds.add(recipientId);
      return true;
    });

    if (uniqueRecipients.length === 0) return;

    const recipientIdsWithAccess = new Set<string>();
    await Promise.all(
      uniqueRecipients.map(async (recipient) => {
        const recipientId = recipient.id;
        try {
          const recipientUser = await resolveUserById(context, recipientId);
          if (!recipientUser) return;
          const hasAccess = await internalLoadById(context, recipientUser, entity.internal_id ?? entity.id);
          if (hasAccess) {
            recipientIdsWithAccess.add(recipientId);
          }
        } catch {
          // Recipient is ignored when user resolution or access check fails.
        }
      }),
    );

    const recipientsWithAccess = uniqueRecipients.filter((recipient) => recipientIdsWithAccess.has(recipient.id));
    if (recipientsWithAccess.length === 0) return;

    const entityName = extractEntityRepresentativeName(entity) || entity.entity_type;
    const results = await Promise.allSettled(
      recipientsWithAccess.map((recipient) => {
        const recipientId = recipient.id;
        const notificationPayload: NotificationAddInput = {
          is_read: false,
          name: entityName,
          notification_type: 'live',
          user_id: recipientId,
          created: now(),
          created_at: now(),
          updated_at: now(),
          notification_content: [{
            title: entityName,
            events: [{
              operation: 'update',
              message: `[${eventName}] ${comment}`,
              instance_id: entity.internal_id ?? entity.id,
              entity_type: entity.entity_type,
            }],
          }],
        };
        return addNotification(context, SYSTEM_USER, notificationPayload);
      }),
    );
    results
      .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
      .forEach(({ reason }) => {
        logApp.error('[OPENCTI-MODULE] Failed to send workflow notification to recipient', { cause: reason });
      });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Failed to send workflow transition comment notifications', { cause: error });
  }
};

interface WorkflowInstanceStoreEntity extends BasicStoreEntity {
  currentState: string;
  completed?: boolean;
  history: string;
  pendingStatus?: string | null;
  pendingError?: string | null;
  pendingTransition?: string | null;
  entity_id: string;
  /**
   * Scope tag for this instance — `'standard'` by default, or the `StatusScope` value of the
   * `Status` the instance was initialized from when the entity was created with an explicit,
   * resolvable `x_opencti_workflow_id` (e.g. `'REQUEST_ACCESS'`). Missing on rows created before
   * this field existed — treat as `'standard'`.
   */
  scope?: string;
}

export const getWorkflowConfig = async (
  context: AuthContext,
  user: AuthUser,
  targetType: string,
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  const executionContext = bypassDraftContext(context);
  return findEntitySettingByType(executionContext, bypassDraftUser(user), targetType);
};

/**
 * Id of the workflow definition an entity setting holds for a scope. There is no fallback between
 * scopes: a request-access lookup never resolves to the Global definition, nor the reverse.
 */
export const resolveScopedDefinitionId = (
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  scope: StatusScope,
): string | undefined => {
  if (scope === StatusScope.RequestAccess) {
    const definitionId = entitySetting?.request_access_workflow?.workflow_definition_id ?? undefined;
    // Both scopes pointing at one definition is a leftover of the two sharing the default name (see
    // resolveDefinitionEntityName): it is the Global one, so the request access scope has none yet.
    return definitionId && definitionId === entitySetting?.workflow_id ? undefined : definitionId;
  }
  return entitySetting?.workflow_id ?? undefined;
};

/**
 * Name of the WorkflowDefinition entity. Its id is derived from the name, so two definitions of one
 * entity type must never share one, or the second is an upsert of the first. Each scope gets its own
 * default, and a name that is the other scope's default is replaced by this scope's.
 */
export const resolveDefinitionEntityName = (entityType: string, scope: StatusScope, name?: string | null): string => {
  const globalDefaultName = `Workflow for ${entityType}`;
  const requestAccessDefaultName = `Request access workflow for ${entityType}`;
  if (scope === StatusScope.RequestAccess) {
    return !name || name === globalDefaultName ? requestAccessDefaultName : name;
  }
  return !name || name === requestAccessDefaultName ? globalDefaultName : name;
};

export const assertScopeAllowed = (entityType: string, scope: StatusScope): void => {
  if (scope !== StatusScope.Global && entityType !== ENTITY_TYPE_CONTAINER_CASE_RFI) {
    throw FunctionalError('Workflow scope is not available for this entity type', { entityType, scope });
  }
};

/**
 * Get workflow definition data based on allowDraft parameter.
 */
export const getDefinitionData = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  allowDraft: boolean = false,
  scope: StatusScope = StatusScope.Global,
): Promise<WorkflowDefinitionResponse | null> => {
  const definitionId = resolveScopedDefinitionId(entitySetting, scope);
  if (definitionId) {
    const executionContext = bypassDraftContext(context);
    const workflowDefinitionEntity = await storeLoadById(
      executionContext,
      bypassDraftUser(user),
      definitionId,
      ENTITY_TYPE_WORKFLOW_DEFINITION,
    ) as WorkflowDefinitionEntity | undefined;
    if (workflowDefinitionEntity) {
      // Choose version based on allowDraft parameter
      let version;
      if (allowDraft) {
        // For UI editing: draft_version if exists, otherwise published_version
        version = workflowDefinitionEntity.draft_version || workflowDefinitionEntity.published_version;
      } else {
        // For runtime execution: ONLY published_version (no fallback)
        version = workflowDefinitionEntity.published_version;
      }

      if (!version?.content) return null;

      const workflowContent = typeof version.content === 'string'
        ? JSON.parse(version.content)
        : version.content;

      // Determine if draft and published are the same
      const draftVersion = workflowDefinitionEntity.draft_version;
      const publishedVersion = workflowDefinitionEntity.published_version;
      const published = !draftVersion || (publishedVersion?.id === draftVersion?.id);
      const errors = version.validation_errors || [];

      return {
        ...workflowContent,
        id: workflowDefinitionEntity.id,
        name: workflowDefinitionEntity.name,
        published,
        hasPublishedVersion: !!publishedVersion,
        errors,
      };
    }
  }

  return null;
};

const findWorkflowInstanceEntity = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<WorkflowInstanceStoreEntity | null> => {
  // Find existing instance via entity_id attribute directly (more robust than relationship)
  const executionContext = bypassDraftContext(context);
  return await loadEntity(executionContext, bypassDraftUser(user), [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['entity_id'], values: [entityId] }],
      filterGroups: [],
    },
  }) as WorkflowInstanceStoreEntity;
};

const findStatusInCache = async (
  context: AuthContext,
  statusId: string | null | undefined,
): Promise<BasicWorkflowStatus | null> => {
  if (!statusId) return null;
  const statuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, SYSTEM_USER, ENTITY_TYPE_STATUS);
  return statuses.find((s) => s.internal_id === statusId) ?? null;
};

/**
 * Resolves a caller-supplied `x_opencti_workflow_id` (a `Status`) to a workflow state at
 * entity-creation time. Returns `null` if the status doesn't exist or doesn't map to any state
 * of the published definition — the caller must not treat this as an error, only as "not
 * resolvable" (case (b) of the three-case creation logic below).
 */
const resolveSuppliedStatus = (
  definitionData: WorkflowDefinitionResponse,
  status: BasicWorkflowStatus | null,
): string | null => {
  if (!status) return null;
  // A state can be declared only via `initialState` or a transition endpoint, not in `states[]`.
  const canonicalStateIds = extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]);
  return canonicalStateIds.has(status.template_id) ? status.template_id : null;
};

/**
 * Resolves the Status currently set on an entity to a state of the published workflow, or `null`
 * when it maps to no state for the instance scope. Reads statuses from the cache: this runs on
 * every external status write.
 */
const resolveEntityStatusState = async (
  context: AuthContext,
  definitionData: WorkflowDefinitionResponse,
  instanceScope: string | undefined,
  statusId: string,
): Promise<string | null> => {
  const status = await findStatusInCache(context, statusId);
  if (!status || status.scope !== resolveProjectionScope(instanceScope)) return null;
  const canonicalStateIds = extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]);
  return canonicalStateIds.has(status.template_id) ? status.template_id : null;
};

/**
 * Scope and published definition an entity runs on. The scope is the instance's, set once at
 * creation; only an entity without instance yet takes it from the status it is created with. The
 * definition is the one the entity setting holds for that scope, never another scope's.
 */
export const resolveInstanceDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  instanceEntity: WorkflowInstanceStoreEntity | null,
  suppliedStatus: BasicWorkflowStatus | null,
): Promise<{ scope: StatusScope; definitionData: WorkflowDefinitionResponse | null }> => {
  const scope = resolveProjectionScope(instanceEntity?.scope ?? suppliedStatus?.scope);
  const definitionData = await getDefinitionData(context, user, entitySetting, false, scope);
  return { scope, definitionData };
};

const hasWorkflowDefinition = (entitySetting: BasicStoreEntityEntitySetting | undefined): boolean => {
  return !!resolveScopedDefinitionId(entitySetting, StatusScope.Global) || !!resolveScopedDefinitionId(entitySetting, StatusScope.RequestAccess);
};

// What was looked up to resolve an entity's definition: `instanceEntity` null means no instance exists yet
interface ResolvedEntityWorkflow {
  instanceEntity: WorkflowInstanceStoreEntity | null;
  suppliedStatus: BasicWorkflowStatus | null;
  scope: StatusScope;
}

// The instance row and, while the entity has none, the status its instance will be created from
const resolveEntityDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entity: { id?: string; internal_id?: string; x_opencti_workflow_id?: string },
  entitySetting: BasicStoreEntityEntitySetting | undefined,
): Promise<ResolvedEntityWorkflow & { definitionData: WorkflowDefinitionResponse | null }> => {
  if (!hasWorkflowDefinition(entitySetting)) {
    return { instanceEntity: null, suppliedStatus: null, scope: StatusScope.Global, definitionData: null };
  }
  const instanceEntity = await findWorkflowInstanceEntity(context, user, (entity.internal_id || entity.id) as string);
  const suppliedStatus = instanceEntity ? null : await findStatusInCache(context, entity.x_opencti_workflow_id);
  return { instanceEntity, suppliedStatus, ...await resolveInstanceDefinition(context, user, entitySetting, instanceEntity, suppliedStatus) };
};

/** Longest request record accepted: a request names a few entities and organizations, far below this. */
export const REQUEST_ACCESS_MAX_LENGTH = 100_000;

// A request record is a JSON object of bounded size: anything else is no request
const isRequestAccessRecord = (rawRequestAccess: unknown): boolean => {
  if (typeof rawRequestAccess !== 'string' || rawRequestAccess.length > REQUEST_ACCESS_MAX_LENGTH) return false;
  try {
    const requestAccess = JSON.parse(rawRequestAccess);
    return !!requestAccess && typeof requestAccess === 'object';
  } catch {
    return false;
  }
};

const hasRequestAccess = (entity: BasicStoreCommon): boolean => {
  return isRequestAccessRecord((entity as { x_opencti_request_access?: unknown }).x_opencti_request_access);
};

/**
 * Where the request of an RFI stands on the published request-access workflow, or null when it runs on the
 * legacy flow. The state is the instance's, or for an RFI without instance yet the one its instance will be
 * created at. Read as the system: a caller who cannot read the definition must not be moved to the legacy flow.
 */
export const resolveRequestAccessWorkflowState = async (
  context: AuthContext,
  rfi: BasicStoreEntity,
): Promise<{ definitionData: WorkflowDefinitionResponse; instanceEntity: WorkflowInstanceStoreEntity | null; currentState: string } | null> => {
  if (!isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG) || rfi.entity_type !== ENTITY_TYPE_CONTAINER_CASE_RFI || !hasRequestAccess(rfi)) {
    return null;
  }
  const entitySetting = await getWorkflowConfig(context, SYSTEM_USER, rfi.entity_type);
  const { scope, definitionData, instanceEntity, suppliedStatus } = await resolveEntityDefinition(context, SYSTEM_USER, rfi, entitySetting);
  if (scope !== StatusScope.RequestAccess || !definitionData) {
    return null;
  }
  const currentState = instanceEntity?.currentState ?? resolveSuppliedStatus(definitionData, suppliedStatus) ?? definitionData.initialState;
  return { definitionData, instanceEntity, currentState };
};

const initializeWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { id?: string; internal_id?: string; x_opencti_workflow_id?: string },
  definitionData: WorkflowDefinitionResponse,
  { scope, suppliedStatus }: Pick<ResolvedEntityWorkflow, 'scope' | 'suppliedStatus'>,
): Promise<WorkflowInstanceStoreEntity> => {
  const entityId = entity.id || entity.internal_id;
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  // Resolve-then-project: three cases —
  // (a) explicit status resolves to a valid state: start there, no projection write.
  // (b) explicit status does not resolve: start at initialState with a pendingError
  //     diagnostic, no projection write — the caller-supplied field is never overwritten.
  // (c) no status supplied: start at initialState and project it onto the entity.
  let currentState = definitionData.initialState;
  // `scope` is the one the definition was resolved with. Global keeps the default 'standard' unless a supplied status resolved.
  let instanceScope: string = scope === StatusScope.Global ? 'standard' : scope;
  let pendingError: string | undefined;
  let shouldProject = false;

  const suppliedStatusId = entity.x_opencti_workflow_id;
  if (suppliedStatusId) {
    const resolvedStateId = resolveSuppliedStatus(definitionData, suppliedStatus);
    if (resolvedStateId) {
      currentState = resolvedStateId;
      instanceScope = scope;
    } else {
      pendingError = `Supplied x_opencti_workflow_id "${suppliedStatusId}" does not resolve to any state of the published workflow`;
    }
  } else {
    shouldProject = true;
  }

  const instanceInput: Record<string, unknown> = {
    entity_id: entityId,
    workflow_id: definitionData.id,
    currentState,
    scope: instanceScope,
    history: JSON.stringify([{
      state: currentState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: 'initialization',
    }]),
  };
  if (pendingError) {
    instanceInput.pendingError = pendingError;
  }

  const instance = await createEntity(executionContext, executionUser, instanceInput, ENTITY_TYPE_WORKFLOW_INSTANCE) as WorkflowInstanceStoreEntity;

  await createRelation(executionContext, executionUser, {
    fromId: entityId,
    toId: instance.id || instance.internal_id,
    relationship_type: RELATION_HAS_WORKFLOW,
  });

  if (shouldProject) {
    // Only the Global scope is reconciled by the status mapping today; 'standard'
    // (this function's default when no explicit status was supplied) maps onto it.
    await projectWorkflowState(executionContext, executionUser, entity as BasicStoreEntity, currentState, StatusScope.Global);
  }

  return instance;
};

/**
 * Return the workflow instance an entity already has (as found by `resolved`), or create one and
 * fire the onEnter hooks of the initial state (sync only). Shared by triggerWorkflowEvent
 * and initializeEntityWorkflow so initialization is never duplicated.
 */
const ensureWorkflowInstance = async (
  executionContext: AuthContext,
  executionUser: AuthUser,
  entity: any,
  definitionData: any,
  resolved: ResolvedEntityWorkflow,
  runInitialActions = true,
): Promise<WorkflowInstanceStoreEntity> => {
  if (resolved.instanceEntity) return resolved.instanceEntity;

  const instanceEntity = await initializeWorkflowInstance(
    executionContext,
    executionUser,
    entity as BasicStoreEntity & { id?: string; internal_id?: string },
    definitionData,
    resolved,
  );

  if (!runInitialActions) return instanceEntity;

  // Run onEnter of the initial state (sync only for now)
  const definition = WorkflowFactory.createDefinition(definitionData);
  const workflowContext = {
    entity,
    user: WORKFLOW_MANAGER_USER,
    triggeringUser: executionUser,
    context: executionContext,
    runtimeParams: {},
    __createListTask: createListTask,
    __workflowInstanceId: instanceEntity.internal_id || instanceEntity.id,
    __draftEntityIds: [],
  };
  const instance = WorkflowFactory.getInstance(definitionData, definition, definitionData.initialState, workflowContext);
  await instance.start();

  return instanceEntity;
};

/**
 * Get workflow definition for an entity type.
 */
export const getWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  allowDraft: boolean = false,
  scope: StatusScope = StatusScope.Global,
): Promise<WorkflowDefinitionResponse | null> => {
  assertScopeAllowed(entityType, scope);
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  return getDefinitionData(context, user, entitySetting, allowDraft, scope);
};

/**
 * Lightweight, non-admin-gated check for whether an entity type currently has a *published*
 * WorkflowDefinition. Used by the frontend's `StatusField` shared guard to decide whether the
 * legacy free-choice Status dropdown must become read-only for that type — deliberately exposed
 * at a lower auth level than `workflowDefinition` (which is `SETTINGS_SETCUSTOMIZATION`-gated and
 * returns the full definition content), since knowledge editors need this boolean on every entity
 * edition form, not just settings admins.
 */
export const hasPublishedWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<boolean> => {
  const definitionData = await getWorkflowDefinition(context, user, entityType, false);
  return !!definitionData;
};

/**
 * Returns the ID of the published version for the given entity setting's workflow, or null if not published.
 */
export const getWorkflowPublishedVersionId = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting,
  scope: StatusScope = StatusScope.Global,
): Promise<string | null> => {
  const definitionId = resolveScopedDefinitionId(entitySetting, scope);
  if (!definitionId) return null;
  const executionContext = bypassDraftContext(context);
  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    bypassDraftUser(user),
    definitionId,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  return workflowDefinitionEntity?.published_version?.id ?? null;
};

/**
 * Gathers the `Status`/`StatusTemplate` input data for `entityType` (all scopes, matching
 * `byScope`'s shape) and hands it to the pure `convertStatusToDefinition`.
 */
// Rejects, before reading any data, an entity type that has no workflow setting for the scope (or
// does not exist), and DraftWorkspace, whose workflow must contain a validateDraft action a migrated
// one never has.
const assertMigratableEntityType = (entityType: string, scope: StatusScope = StatusScope.Global) => {
  assertScopeAllowed(entityType, scope);
  validateSetting(entityType, scope === StatusScope.RequestAccess ? 'request_access_workflow' : 'workflow_id');
  if (entityType === ENTITY_TYPE_DRAFT_WORKSPACE) {
    throw FunctionalError('DraftWorkspace statuses cannot be migrated: its workflow must contain a validateDraft action', { entityType });
  }
};

const convertLegacyStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<ConvertStatusToDefinitionResult & { statuses: BasicWorkflowStatus[] }> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const allStatuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['type'], values: [entityType] }],
      filterGroups: [],
    },
  });
  // A status marked `to_be_deleted_at` is a state an admin removed in an earlier republish: migrating
  // it again would bring it back and clear its deletion mark on publish. One that an entity still
  // references is kept, so that entity lands in a state the migrated workflow knows.
  const statuses: BasicWorkflowStatus[] = [];
  for (const status of allStatuses) {
    if (!status.to_be_deleted_at || await isStatusReferencedByEntity(executionContext, executionUser, entityType, status.id)) {
      statuses.push(status);
    }
  }
  const templateIds = [...new Set(statuses.map((status) => status.template_id))];
  const templates = templateIds.length > 0
    ? await storeLoadByIds<BasicWorkflowTemplateEntity>(executionContext, executionUser, templateIds, ENTITY_TYPE_STATUS_TEMPLATE)
    : [];
  // storeLoadByIds returns an undefined entry for each id it couldn't find — filter those out
  // before handing templates to the converter (a missing one becomes a MISSING_TEMPLATE diagnostic).
  const conversion = convertStatusToDefinition(statuses, templates.filter((template): template is BasicWorkflowTemplateEntity => template != null));
  return { ...conversion, statuses };
};

// The legacy approved / declined ids point at REQUEST_ACCESS `Status` records; their templates are
// the states the migrated definition marks as outcomes. When they cannot be, the group is kept as
// is with a blocking REQUEST_ACCESS_OUTCOME_INVALID diagnostic.
const convertRequestAccessScope = (
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  statuses: BasicWorkflowStatus[],
  result: WorkflowMigrationConversionResult,
): WorkflowMigrationConversionResult => {
  const resolveTemplateId = (statusId: string | undefined) => statuses
    .find((status) => status.id === statusId && status.scope === StatusScope.RequestAccess)?.template_id;
  const requestAccessConfiguration = entitySetting?.request_access_workflow;
  return tryConvertRequestAccessGroup(
    result,
    resolveTemplateId(requestAccessConfiguration?.approved_workflow_id),
    resolveTemplateId(requestAccessConfiguration?.declined_workflow_id),
  );
};

export interface WorkflowMigrationPreviewData extends ConvertStatusToDefinitionResult {
  publishedByScope: Partial<Record<StatusScope, boolean>>;
}

/**
 * Read-only preview of what migrating an entity type's legacy `Status` set to a
 * `WorkflowDefinition` would produce, one result per `StatusScope` the type can migrate (GLOBAL,
 * plus REQUEST_ACCESS for Case-Rfi, converted as `workflowMigrate` would) — no persisted changes.
 * When the entity type already has a workflow for a scope, that scope's statuses are managed by it
 * rather than legacy data: its result then carries an EXISTING_WORKFLOW diagnostic, and
 * `publishedByScope` reports whether that workflow has a published version.
 */
export const getWorkflowMigrationPreview = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<WorkflowMigrationPreviewData> => {
  assertMigratableEntityType(entityType);
  const { byScope, statuses } = await convertLegacyStatuses(context, user, entityType);
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const scopes = entityType === ENTITY_TYPE_CONTAINER_CASE_RFI ? [StatusScope.Global, StatusScope.RequestAccess] : [StatusScope.Global];
  const requestAccessResult = byScope[StatusScope.RequestAccess];
  if (!scopes.includes(StatusScope.RequestAccess)) {
    delete byScope[StatusScope.RequestAccess];
  } else if (requestAccessResult && requestAccessResult.definition.states.length > 0) {
    byScope[StatusScope.RequestAccess] = convertRequestAccessScope(entitySetting, statuses, requestAccessResult);
  }
  const publishedByScope: Partial<Record<StatusScope, boolean>> = {};
  for (const scope of scopes) {
    if (!entitySetting || !resolveScopedDefinitionId(entitySetting, scope)) continue;
    const isPublished = !!(await getWorkflowPublishedVersionId(context, user, entitySetting, scope));
    const workflowLabel = scope === StatusScope.RequestAccess ? 'request access workflow' : 'workflow';
    // Reported even when no status of the scope is left to migrate, so the preview never hides the workflow.
    const scopeResult = byScope[scope] ?? { definition: { initialState: '', states: [], transitions: [] }, diagnostics: [] };
    scopeResult.diagnostics.push({
      type: 'EXISTING_WORKFLOW',
      message: isPublished
        ? `Entity type already has a published ${workflowLabel}; its statuses are managed by that workflow, and migration cannot replace it.`
        : `Entity type already has a ${workflowLabel} with no published version; migrating replaces its draft only with overwrite: true.`,
    });
    byScope[scope] = scopeResult;
    publishedByScope[scope] = isPublished;
  }
  return { byScope, publishedByScope };
};

const getWorkflowMigrateLockKey = (entityType: string): string => `workflow-migrate:${entityType}`;

// Undoes a first-time migration whose publish failed: the type goes back to having no workflow for
// the scope, so a retry does not need `overwrite`.
const removeMigratedWorkflow = async (context: AuthContext, user: AuthUser, entityType: string, scope: StatusScope) => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const definitionId = resolveScopedDefinitionId(entitySetting, scope);
  if (!definitionId) return;
  await deleteWorkflowDefinition(context, user, entityType, scope);
  await deleteElementById(bypassDraftContext(context), bypassDraftUser(user), definitionId, ENTITY_TYPE_WORKFLOW_DEFINITION);
};

/**
 * One-shot migration of an entity type's legacy `Status` set of one scope into a workflow
 * definition: saved as a draft, then published when `publish` is true. Reuses
 * `setWorkflowDefinition` / `publishWorkflowDefinition`, so validation, EE checks and status
 * locking are the same as a hand-authored workflow. GLOBAL migrates the entity type's workflow;
 * REQUEST_ACCESS (Case-Rfi only) migrates its request access statuses into the request access
 * workflow, with the configured approved / declined statuses as outcome states. Existing `Status`
 * records are reused, so no entity changes status.
 *
 * - Refuses to replace an existing workflow unless `overwrite` is true, and never replaces one that
 *   has a published version: its conditions, actions and hooks would be lost in a migrated mesh.
 * - Never saves a state whose template no longer exists (MISSING_TEMPLATE), and never publishes a
 *   definition the preview flagged with another blocking diagnostic, nor one that fails validation:
 *   all are checked before anything is saved. Publishing also needs the
 *   ENTITIES_WORKFLOW feature, without which the workflow is not applied to entity writes.
 * - Runs under a per-type lock from the existence check to the publish, and removes the workflow it
 *   created when the publish fails, so a retry starts from the same state.
 */
export const migrateWorkflowFromStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  publish: boolean,
  overwrite = false,
  scope: StatusScope = StatusScope.Global,
): Promise<EntitySettingWithWorkflowResponse> => {
  assertMigratableEntityType(entityType, scope);
  if (publish && !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
    throw FunctionalError('Cannot publish a migrated workflow while the ENTITIES_WORKFLOW feature is disabled; migrate without publishing', { entityType });
  }
  const lock = await lockResources([getWorkflowMigrateLockKey(entityType)]);
  try {
    const entitySetting = await getWorkflowConfig(context, user, entityType);
    if (!entitySetting) {
      throw FunctionalError('Entity setting not found for type', { entityType });
    }
    const existingDefinitionId = resolveScopedDefinitionId(entitySetting, scope);
    if (existingDefinitionId) {
      if (!overwrite) {
        throw FunctionalError('Entity type already has a workflow, migration would overwrite it (pass overwrite: true to replace it)', { entityType, scope });
      }
      if (await getWorkflowPublishedVersionId(context, user, entitySetting, scope)) {
        throw FunctionalError('Entity type already has a published workflow; migration only replaces a workflow that was never published', { entityType, scope });
      }
    }

    const { byScope, statuses } = await convertLegacyStatuses(context, user, entityType);
    const picked = pickMigrationScope(entityType, byScope, scope);
    const { definition, diagnostics } = scope === StatusScope.RequestAccess
      ? convertRequestAccessScope(entitySetting, statuses, picked)
      : picked;
    const invalidOutcomes = diagnostics.filter((diagnostic) => diagnostic.type === 'REQUEST_ACCESS_OUTCOME_INVALID');
    if (invalidOutcomes.length > 0) {
      throw FunctionalError(invalidOutcomes.map((diagnostic) => diagnostic.message).join('; '), {
        entityType,
        approvedStatusId: entitySetting.request_access_workflow?.approved_workflow_id,
        declinedStatusId: entitySetting.request_access_workflow?.declined_workflow_id,
      });
    }
    // Validation only checks state ids that are not declared in `states`, and a migrated definition
    // declares them all: a state whose template is gone would pass a later plain publish. Refuse it
    // here, even for a draft.
    const missingTemplates = diagnostics.filter((diagnostic) => diagnostic.type === 'MISSING_TEMPLATE');
    if (missingTemplates.length > 0) {
      throw FunctionalError('Cannot migrate: some statuses reference a status template that no longer exists', {
        entityType,
        diagnostics: missingTemplates.map((diagnostic) => diagnostic.message),
      });
    }
    const definitionContent = JSON.stringify(definition);
    if (publish) {
      const blocking = getPublishBlockingDiagnostics(diagnostics);
      if (blocking.length > 0) {
        throw FunctionalError('Cannot publish migrated workflow: resolve the blocking diagnostics first, or migrate without publishing', {
          entityType,
          diagnostics: blocking.map((diagnostic) => diagnostic.message),
        });
      }
      const validationErrors = await validateWorkflowDefinitionData(
        bypassDraftContext(context),
        bypassDraftUser(user),
        definitionContent,
        entityType,
        existingDefinitionId,
        scope,
      );
      if (validationErrors.length > 0) {
        throw FunctionalError('Cannot publish migrated workflow: the migrated definition is invalid', {
          entityType,
          errors: validationErrors.map((error) => error.message),
        });
      }
    }

    let result = await setWorkflowDefinition(context, user, entityType, definitionContent, scope);
    if (publish) {
      try {
        result = await publishWorkflowDefinition(context, user, entityType, scope);
      } catch (error) {
        if (!existingDefinitionId) {
          await removeMigratedWorkflow(context, user, entityType, scope);
        }
        throw error;
      }
    }
    if (scope === StatusScope.RequestAccess) {
      addWorkflowRequestAccessMigrationCount();
    }
    return result;
  } finally {
    await lock.unlock();
  }
};

/**
 * Create or update workflow definition for an entity type.
 */
export const setWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definition: string,
  scope: StatusScope = StatusScope.Global,
): Promise<EntitySettingWithWorkflowResponse> => {
  assertScopeAllowed(entityType, scope);
  validateSetting(entityType, scope === StatusScope.RequestAccess ? 'request_access_workflow' : 'workflow_id');

  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }
  const existingDefinitionId = resolveScopedDefinitionId(entitySetting, scope);

  // Validate definition is valid JSON and respect schema
  let definitionObj;
  try {
    definitionObj = JSON.parse(definition);
  } catch (_error) {
    throw FunctionalError('Invalid workflow definition JSON');
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const errors = await validateWorkflowDefinitionData(executionContext, executionUser, definition, entityType, existingDefinitionId, scope);

  // Check if the definition uses EE-only features (actions/conditions on transitions
  // or onEnter/onExit actions on states), except for the 'validateDraft' action which is CE.
  const definitionRequiresEE = (
    (definitionObj.transitions ?? []).some((t: WorkflowSerializedTransition) => (
      hasEEActions(t.asyncActions)
      || hasEEActions(t.syncActions)
      || hasConditions(t.conditions)
      || !!t.comment
    ))
    || (definitionObj.states ?? []).some((s: WorkflowSerializedState) => hasEEActions(s.onEnter) || hasEEActions(s.onExit))
  );
  if (definitionRequiresEE) {
    await checkEnterpriseEdition(context);
  }

  const workflowName = resolveDefinitionEntityName(entityType, scope, definitionObj.name);
  // The entity id derives from the name: reusing the other scope's name would upsert its definition,
  // overwriting its draft and history.
  const otherScopeDefinitionId = resolveScopedDefinitionId(entitySetting, scope === StatusScope.Global ? StatusScope.RequestAccess : StatusScope.Global);
  if (otherScopeDefinitionId && otherScopeDefinitionId !== existingDefinitionId) {
    const otherScopeDefinition = await storeLoadById(
      executionContext,
      executionUser,
      otherScopeDefinitionId,
      ENTITY_TYPE_WORKFLOW_DEFINITION,
    ) as WorkflowDefinitionEntity | undefined;
    if (otherScopeDefinition?.name === workflowName) {
      throw FunctionalError('The Global and Request access workflows must have different names', { entityType, scope, name: workflowName });
    }
  }

  // Create version data structure
  const versionData = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    createdBy: executionUser.id,
    content: definition,
    validation_errors: errors,
  };

  // 1. Check if we have an existing workflow linked
  if (existingDefinitionId) {
    const existingWorkflow = await storeLoadById(
      executionContext,
      executionUser,
      existingDefinitionId,
      ENTITY_TYPE_WORKFLOW_DEFINITION,
    ) as WorkflowDefinitionEntity | undefined;
    if (existingWorkflow) {
      // Add to version history (prepend new version to maintain chronological order).
      // Cap at 100 entries to prevent unbounded growth (e.g. from a save loop triggered by UI hooks).
      const MAX_VERSIONS = 100;
      const allVersions = existingWorkflow.all_versions || [];
      const updatedVersions = [versionData, ...allVersions].slice(0, MAX_VERSIONS);

      // draft_version is always in all_versions
      await updateAttribute(executionContext, executionUser, existingWorkflow.id, ENTITY_TYPE_WORKFLOW_DEFINITION, [
        { key: 'draft_version', value: [versionData] },
        { key: 'all_versions', value: updatedVersions },
        { key: 'name', value: [workflowName] },
      ]);

      const updatedWorkflow = await storeLoadById(
        executionContext,
        executionUser,
        existingWorkflow.id,
        ENTITY_TYPE_WORKFLOW_DEFINITION,
      ) as WorkflowDefinitionEntity;
      validateVersionConsistency(updatedWorkflow);

      // Check if draft matches published
      const published = updatedWorkflow.published_version?.id === versionData.id;

      return {
        ...entitySetting,
        workflow_id: existingDefinitionId,
        errors,
        published,
      } as EntitySettingWithWorkflowResponse;
    }
  }

  // 2. Create the WorkflowDefinition entity
  // Initial draft_version is in all_versions
  const workflowDefinitionInput = {
    name: workflowName,
    draft_version: versionData,
    all_versions: [versionData],
  };
  const workflowDefinition = await createEntity(
    executionContext,
    executionUser,
    workflowDefinitionInput,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity;

  // Validate consistency after creation
  validateVersionConsistency(workflowDefinition);

  // 3. Link it to the EntitySetting. The request access configuration is written as a whole object:
  // read it again here so a concurrent edit made since the start of this call is not overwritten.
  const currentRequestAccess = scope === StatusScope.RequestAccess
    ? (await getWorkflowConfig(context, user, entityType) ?? entitySetting).request_access_workflow
    : undefined;
  const linkInput: EditInput = scope === StatusScope.RequestAccess
    ? { key: 'request_access_workflow', value: [{ approval_admin: [], ...currentRequestAccess, workflow_definition_id: workflowDefinition.id }] }
    : { key: 'workflow_id', value: [workflowDefinition.id] };
  const { element } = await updateAttribute(executionContext, executionUser, entitySetting.id, 'EntitySetting', [linkInput]);

  // New workflows have no published version yet
  const published = false;

  const elementWithSetting = element as unknown as BasicStoreEntityEntitySetting;
  return {
    id: elementWithSetting.id,
    workflow_id: workflowDefinition.id,
    target_type: elementWithSetting.target_type,
    errors,
    published,
  } as EntitySettingWithWorkflowResponse;
};

/**
 * Delete workflow definition for an entity type.
 */
export const deleteWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope = StatusScope.Global,
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  assertScopeAllowed(entityType, scope);
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (entitySetting && resolveScopedDefinitionId(entitySetting, scope)) {
    const executionContext = bypassDraftContext(context);
    let unlinkInput: EditInput = { key: 'workflow_id', value: [null] };
    if (scope === StatusScope.RequestAccess) {
      const { workflow_definition_id: _unlinked, ...requestAccessConfiguration } = entitySetting.request_access_workflow!;
      unlinkInput = { key: 'request_access_workflow', value: [requestAccessConfiguration] };
    }
    const { element } = await updateAttribute(executionContext, bypassDraftUser(user), entitySetting.id, 'EntitySetting', [unlinkInput]);
    return element as unknown as BasicStoreEntityEntitySetting;
  }
  return entitySetting;
};

/**
 * Ensures every canonical workflow state (StatusTemplate reference) has a matching `Status`
 * record for this entity type in the Global scope, creating any that are missing and syncing the
 * `order` of any that already exist.
 *
 * Uses `extractCanonicalStateIds` rather than iterating `definitionData.states` directly, since
 * validation allows a state to be referenced only as `initialState` or a transition endpoint
 * (from/to) without an explicit entry in `states`, as long as it resolves to an existing
 * StatusTemplate — the engine registers those states too, so skipping them here would leave the
 * full-status-mapping invariant unenforced for implicit states.
 *
 * The `order` sync is a self-healing backward-compatibility measure rather than a one-off
 * migration: a `Status` published before ordering was computed from the transition graph (e.g.
 * the built-in DraftWorkspace workflow) may carry a stale/default `order`. Every republish
 * recomputes it here, so existing definitions naturally converge without requiring a migration.
 *
 * Only the given scope is reconciled here — existing `Status` records in other scopes are
 * left untouched.
 */
export const ensureFullStatusMapping = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definitionData: WorkflowDefinitionData,
  scope: StatusScope = StatusScope.Global,
): Promise<void> => {
  const canonicalStateIds = extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]);
  if (canonicalStateIds.size === 0) return;

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const existingStatuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [entityType] },
        { key: ['scope'], values: [scope] },
      ],
      filterGroups: [],
    },
  });
  const existingStatusByTemplateId = new Map(existingStatuses.map((status) => [status.template_id, status]));

  const computedOrder = computeStateOrder(definitionData.initialState, definitionData.transitions);

  for (const statusId of canonicalStateIds) {
    const order = computedOrder.get(statusId) ?? 0;
    const existingStatus = existingStatusByTemplateId.get(statusId);
    if (!existingStatus) {
      await createStatus(executionContext, executionUser, entityType, {
        template_id: statusId,
        order,
        scope,
      });
    } else if (existingStatus.order !== order) {
      await updateAttribute(executionContext, executionUser, existingStatus.id, ENTITY_TYPE_STATUS, [{ key: 'order', value: [order] }]);
    }
  }
};

// Grace period before an orphaned Status is eligible for hard deletion by the cleanup manager.
const STATUS_DELETION_GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * True if any EntitySetting's request-access workflow (approved/declined) references this
 * `Status` id.
 */
const isStatusReferencedByRequestAccessWorkflow = async (
  context: AuthContext,
  user: AuthUser,
  statusId: string,
): Promise<boolean> => {
  const entitySettings = await fullEntitiesList<BasicStoreEntityEntitySetting>(context, user, [ENTITY_TYPE_ENTITY_SETTING]);
  return entitySettings.some((setting) => (
    setting.request_access_workflow?.approved_workflow_id === statusId
    || setting.request_access_workflow?.declined_workflow_id === statusId
  ));
};

/**
 * On republish, marks `Status` records no longer mapped by any state (and unreferenced by any
 * entity or request-access workflow) as `to_be_deleted_at` for later cleanup, and clears that
 * mark on any `Status` a state maps back to.
 */
const reconcileOrphanedStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  oldDefinitionData: WorkflowDefinitionData,
  newDefinitionData: WorkflowDefinitionData,
  scope: StatusScope = StatusScope.Global,
): Promise<void> => {
  const oldTemplateIds = extractCanonicalStateIds(oldDefinitionData as Parameters<typeof extractCanonicalStateIds>[0]);
  const newTemplateIds = extractCanonicalStateIds(newDefinitionData as Parameters<typeof extractCanonicalStateIds>[0]);

  const existingStatuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [entityType] },
        { key: ['scope'], values: [scope] },
      ],
      filterGroups: [],
    },
  });

  for (const status of existingStatuses) {
    const stillMapped = newTemplateIds.has(status.template_id);

    if (stillMapped) {
      if (status.to_be_deleted_at) {
        // Restore-vs-purge race: the state mapping to this Status was reintroduced before the
        // cleanup manager purged it. Restoring wins.
        await updateAttribute(context, user, status.id, ENTITY_TYPE_STATUS, [{ key: 'to_be_deleted_at', value: [null] }]);
      }
      continue;
    }

    const wasRemoved = oldTemplateIds.has(status.template_id);
    if (!wasRemoved || status.to_be_deleted_at) {
      // Not part of this definition's removed states (pre-existing, unrelated Status), or
      // already marked for deletion by a previous republish — nothing to do.
      continue;
    }

    const referencedByEntity = await isStatusReferencedByEntity(context, user, entityType, status.id);
    if (referencedByEntity) continue;
    const referencedByRequestAccess = await isStatusReferencedByRequestAccessWorkflow(context, user, status.id);
    if (referencedByRequestAccess) continue;

    const toBeDeletedAt = new Date(Date.now() + STATUS_DELETION_GRACE_PERIOD_MS);
    await updateAttribute(context, user, status.id, ENTITY_TYPE_STATUS, [{ key: 'to_be_deleted_at', value: [toBeDeletedAt] }]);
  }
};

/**
 * Re-verifies whether a `Status` previously marked `to_be_deleted_at` is still orphaned, right
 * before the cleanup manager hard-deletes it, since state can change during the grace window.
 */
export const isStatusOrphaned = async (
  context: AuthContext,
  user: AuthUser,
  status: BasicWorkflowStatus,
): Promise<boolean> => {
  const definitionData = await getWorkflowDefinition(context, user, status.type, false, status.scope);
  const stillMapped = !!definitionData
    && extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]).has(status.template_id);
  if (stillMapped) return false;

  const referencedByEntity = await isStatusReferencedByEntity(context, user, status.type, status.id);
  if (referencedByEntity) return false;
  const referencedByRequestAccess = await isStatusReferencedByRequestAccessWorkflow(context, user, status.id);
  if (referencedByRequestAccess) return false;

  return true;
};

/**
 * Lock key shared by `publishWorkflowDefinition` and the workflow status cleanup manager, so
 * cleanup cannot hard-delete a `Status` while a republish is concurrently restoring/recreating it
 * for the same entity type (and vice versa).
 */
export const getWorkflowStatusLockKey = (entityType: string): string => `workflow-status-lifecycle:${entityType}`;

const findStatusesByTemplateIds = (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  templateIds: string[],
  scope: StatusScope,
) => fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
  filters: {
    mode: FilterMode.And,
    filters: [
      { key: ['type'], values: [entityType] },
      { key: ['scope'], values: [scope] },
      { key: ['template_id'], values: templateIds, operator: FilterOperator.Eq, mode: FilterMode.Or },
    ],
    filterGroups: [],
  },
});

/**
 * Request access Approved / Declined markers of the published version cannot leave a state that
 * still holds RFIs, no transition may be added out of such a state, and a marker cannot be newly
 * placed on a state that holds RFIs (they would sit in a terminal outcome with no decision applied).
 * A state holds RFIs when a workflow instance sits in it or an RFI still carries its REQUEST_ACCESS
 * `Status`. The legacy Approved / Declined `Status` of an outcome is not counted for that outcome:
 * its RFIs were already decided that way, which is what the first publish of a migration relies on.
 * `oldDefinitionData` is undefined on the first publish.
 */
const findRequestAccessOutcomeViolations = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  workflowDefinitionId: string,
  oldDefinitionData: WorkflowDefinitionData | undefined,
  newDefinitionData: WorkflowDefinitionData,
): Promise<WorkflowValidationError[]> => {
  const outcomeStatesOf = (definitionData: WorkflowDefinitionData | undefined) => (definitionData?.states ?? [])
    .filter((state) => state.requestAccessOutcome);
  const previousOutcomeStates = outcomeStatesOf(oldDefinitionData);
  const previousOutcomeStateIds = new Map(previousOutcomeStates.map((state) => [state.requestAccessOutcome, state.statusId]));
  const newOutcomeStates = outcomeStatesOf(newDefinitionData);
  const newOutcomeStateIds = new Map(newOutcomeStates.map((state) => [state.requestAccessOutcome, state.statusId]));
  const transitionKeys = (definitionData: WorkflowDefinitionData | undefined) => (definitionData?.transitions ?? [])
    .flatMap((transition) => (Array.isArray(transition.from) ? transition.from : [transition.from]).map((from) => `${from}::${transition.event}::${transition.to}`));
  const previousTransitionKeys = new Set(transitionKeys(oldDefinitionData));
  const addedTransitionKeys = transitionKeys(newDefinitionData).filter((key) => !previousTransitionKeys.has(key));

  const requestAccessConfiguration = (await getWorkflowConfig(context, user, entityType))?.request_access_workflow;
  const legacyOutcomeStatusIds: Record<RequestAccessOutcome, string | undefined> = {
    APPROVED: requestAccessConfiguration?.approved_workflow_id ?? undefined,
    DECLINED: requestAccessConfiguration?.declined_workflow_id ?? undefined,
  };
  const holdsRfis = async (stateId: string, ignoredStatusId?: string) => {
    if (oldDefinitionData && (await findInstancesInStates(context, user, [stateId], workflowDefinitionId)).length > 0) return true;
    const statuses = await findStatusesByTemplateIds(context, user, entityType, [stateId], StatusScope.RequestAccess);
    for (const status of statuses) {
      if (status.id !== ignoredStatusId && await isStatusReferencedByEntity(context, user, entityType, status.id)) return true;
    }
    return false;
  };
  const labelOf = (outcome: RequestAccessOutcome) => (outcome === 'APPROVED' ? 'Approved' : 'Declined');

  const errors: WorkflowValidationError[] = [];
  for (const state of previousOutcomeStates) {
    const moved = newOutcomeStateIds.get(state.requestAccessOutcome) !== state.statusId;
    const gainsTransition = addedTransitionKeys.some((key) => key.startsWith(`${state.statusId}::`));
    if (!moved && !gainsTransition) continue;
    if (!await holdsRfis(state.statusId)) continue;

    const label = labelOf(state.requestAccessOutcome!);
    if (moved) {
      errors.push({
        type: 'REQUEST_ACCESS_OUTCOME_MOVED',
        message: `The ${label} marker cannot leave state '${state.statusId}' while it still holds requests`,
      });
    }
    if (gainsTransition) {
      errors.push({
        type: 'REQUEST_ACCESS_OUTCOME_NOT_TERMINAL',
        message: `No transition can be added out of state '${state.statusId}', the ${label} state of the published version, while it still holds requests`,
      });
    }
  }
  for (const state of newOutcomeStates) {
    const outcome = state.requestAccessOutcome!;
    if (previousOutcomeStateIds.get(outcome) === state.statusId) continue;
    if (!await holdsRfis(state.statusId, legacyOutcomeStatusIds[outcome])) continue;
    errors.push({
      type: 'REQUEST_ACCESS_OUTCOME_PLACED',
      message: `The ${labelOf(outcome)} marker cannot be placed on state '${state.statusId}' while it holds undecided requests`,
    });
  }
  return errors;
};

/**
 * Points the legacy `approved_workflow_id` / `declined_workflow_id` at the REQUEST_ACCESS `Status`
 * mapped to the Approved / Declined states, so every legacy reader keeps working.
 * Must run once the full status mapping exists.
 */
const syncRequestAccessLegacyStatusIds = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definitionData: WorkflowDefinitionData,
): Promise<void> => {
  const outcomeStates = (definitionData.states ?? []).filter((state) => state.requestAccessOutcome);
  if (outcomeStates.length === 0) return;
  const statuses = await findStatusesByTemplateIds(context, user, entityType, outcomeStates.map((state) => state.statusId), StatusScope.RequestAccess);
  const statusIdByTemplateId = new Map(statuses.map((status) => [status.template_id, status.id]));
  const approvedId = statusIdByTemplateId.get(outcomeStates.find((state) => state.requestAccessOutcome === 'APPROVED')?.statusId as string);
  const declinedId = statusIdByTemplateId.get(outcomeStates.find((state) => state.requestAccessOutcome === 'DECLINED')?.statusId as string);

  // Read the setting at write time: the one loaded when publishing started may predate a concurrent
  // edit of the request access configuration, which the whole-object write below would overwrite.
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) return;
  const current = entitySetting.request_access_workflow;
  const approved = approvedId ?? current?.approved_workflow_id;
  const declined = declinedId ?? current?.declined_workflow_id;
  if (approved === current?.approved_workflow_id && declined === current?.declined_workflow_id) return;
  await updateAttribute(context, user, entitySetting.id, ENTITY_TYPE_ENTITY_SETTING, [
    { key: 'request_access_workflow', value: [{ approval_admin: [], ...current, approved_workflow_id: approved, declined_workflow_id: declined }] },
  ]);
};

/**
 * Publish the draft workflow definition (copy draft_version to published_version).
 */
export const publishWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope = StatusScope.Global,
): Promise<EntitySettingWithWorkflowResponse> => {
  assertScopeAllowed(entityType, scope);
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  const definitionId = resolveScopedDefinitionId(entitySetting, scope);
  if (!definitionId) {
    throw FunctionalError('No workflow definition to publish', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    definitionId,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: definitionId });
  }

  const draftVersion = workflowDefinitionEntity.draft_version;
  if (!draftVersion) {
    throw FunctionalError('No draft version to publish', { entityType });
  }

  // Re-validate at publish time rather than trusting the draft's stored `validation_errors`,
  // which were computed at save time and can be stale (e.g. new validation rules added since, or
  // DB state — like status templates — changed after the draft was last saved). Publishing an
  // invalid definition (e.g. missing statusId, unreachable state) must be blocked here.
  const freshValidationErrors = await validateWorkflowDefinitionData(
    executionContext,
    executionUser,
    draftVersion.content,
    entityType,
    definitionId,
    scope,
  );
  if (freshValidationErrors.length > 0) {
    throw FunctionalError('Cannot publish workflow with validation errors', {
      entityType,
      errorCount: freshValidationErrors.length,
    });
  }

  // Hold a lock shared with the workflow status cleanup manager through reconciliation, full-status-
  // mapping and the publication update below. Without it, cleanup could check a Status, a republish
  // here could clear its deletion mark and recreate its mapping, and cleanup would still delete it
  // based on its now-stale check — clearing `to_be_deleted_at` does not cancel a deletion in progress.
  const lock = await lockResources([getWorkflowStatusLockKey(entityType)]);
  try {
    if (scope === StatusScope.RequestAccess) {
      const parseContent = (raw: unknown): WorkflowDefinitionData | undefined => {
        try {
          return (typeof raw === 'string' ? JSON.parse(raw) : raw) as WorkflowDefinitionData;
        } catch (_) {
          return undefined;
        }
      };
      const newDefinitionData = parseContent(draftVersion.content);
      const outcomeErrors = !newDefinitionData ? [] : await findRequestAccessOutcomeViolations(
        executionContext,
        executionUser,
        entityType,
        workflowDefinitionEntity.id,
        workflowDefinitionEntity.published_version ? parseContent(workflowDefinitionEntity.published_version.content) : undefined,
        newDefinitionData,
      );
      if (outcomeErrors.length > 0) {
        throw FunctionalError('Cannot publish workflow with validation errors', {
          entityType,
          errorCount: outcomeErrors.length,
          errors: outcomeErrors,
        });
      }
    }
    // Re-check at publish time: ensure the draft does not remove non-ending states that still have
    // active workflow instances. The validation_errors on the draft were computed at save time and
    // may be stale (instances may have moved into those states since the draft was saved).
    if (workflowDefinitionEntity.published_version) {
      let oldDef: any;
      let newDef: any;
      try {
        const rawOld = workflowDefinitionEntity.published_version.content;
        oldDef = typeof rawOld === 'string' ? JSON.parse(rawOld) : rawOld;
        const rawNew = draftVersion.content;
        newDef = typeof rawNew === 'string' ? JSON.parse(rawNew) : rawNew;
      } catch (_) {
        oldDef = null;
        newDef = null;
      }

      if (oldDef && newDef) {
        // Same rule as validation (shared function): instances in a removed non-ending state block the
        // removal, ending states and completed instances do not.
        const { states: blockingStates, instances: blockingInstances } = await findInstancesBlockingStateRemoval(
          executionContext,
          executionUser,
          oldDef,
          newDef,
          workflowDefinitionEntity.id,
        );
        if (blockingInstances.length > 0) {
          throw FunctionalError(
            'Cannot publish workflow: the following statuses are in use and cannot be removed. Move all items out of those statuses first.',
            { removedStates: blockingStates, entityType: ENTITY_TYPE_STATUS_TEMPLATE },
          );
        }

        // Same guard as validation's STATUS_IN_USE, re-checked here against the correct baseline
        // (published_version, not draftVersion): validateWorkflowDefinitionData above compares the
        // draft against itself at publish time (its own DB lookup still finds draft_version, since
        // it hasn't been cleared yet), so it can never catch a status removed by this same draft.
        const oldStatusIds = extractCanonicalStateIds(oldDef as Parameters<typeof extractCanonicalStateIds>[0]);
        const newStatusIds = extractCanonicalStateIds(newDef as Parameters<typeof extractCanonicalStateIds>[0]);
        const removedStatusIds = [...oldStatusIds].filter((sid) => !newStatusIds.has(sid));

        if (removedStatusIds.length > 0) {
          const removedStatuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
            filters: {
              mode: FilterMode.And,
              filters: [
                { key: ['type'], values: [entityType] },
                { key: ['scope'], values: [scope] },
                { key: ['template_id'], values: removedStatusIds, operator: FilterOperator.Eq, mode: FilterMode.Or },
              ],
              filterGroups: [],
            },
          });

          for (const status of removedStatuses) {
            const referencedByEntity = await isStatusReferencedByEntity(executionContext, executionUser, entityType, status.id);
            if (referencedByEntity) {
              throw FunctionalError(
                'Cannot publish workflow: the following statuses are still assigned to entities and cannot be removed.',
                { removedStatus: status.template_id, entityType: ENTITY_TYPE_STATUS },
              );
            }
          }
        }

        // Republish orphan reconciliation: any Status no longer mapped by the new definition is
        // marked for deferred deletion (grace period) unless still referenced by an entity or by a
        // request-access workflow config; a Status still pending deletion that is reintroduced by
        // the new definition has its pending mark cleared (restore wins over a concurrent purge).
        await reconcileOrphanedStatuses(executionContext, executionUser, entityType, oldDef, newDef, scope);
      }
    }

    // Validate consistency BEFORE publishing
    const allVersions = workflowDefinitionEntity.all_versions || [];
    const draftInHistory = allVersions.some((version: WorkflowVersion) => version.id === draftVersion.id);
    if (!draftInHistory) {
      throw FunctionalError('Consistency error: Cannot publish draft_version that is not in all_versions', {
        draftVersionId: draftVersion.id,
      });
    }

    // Full-mapping invariant: every state in the definition being published must map to a real
    // Status record, creating any missing ones before the definition is marked published.
    let publishedDefinitionData: WorkflowDefinitionData | null = null;
    try {
      const rawContent = draftVersion.content;
      publishedDefinitionData = typeof rawContent === 'string' ? JSON.parse(rawContent) : rawContent;
    } catch (_) {
      // Malformed content will already have failed validation earlier; nothing to reconcile here.
    }
    if (publishedDefinitionData) {
      await ensureFullStatusMapping(executionContext, executionUser, entityType, publishedDefinitionData, scope);
      if (scope === StatusScope.RequestAccess) {
        await syncRequestAccessLegacyStatusIds(executionContext, executionUser, entityType, publishedDefinitionData);
      }
    }

    // CONSISTENCY GUARANTEE: published_version will be in all_versions (already there via draft)
    // Copy draft_version to published_version and clear the draft (no more unpublished changes).
    const updates: EditInput[] = [
      { key: 'published_version', value: [draftVersion] },
      { key: 'draft_version', value: [] },
    ];

    await updateAttribute(executionContext, executionUser, workflowDefinitionEntity.id, ENTITY_TYPE_WORKFLOW_DEFINITION, updates);
  } finally {
    await lock.unlock();
  }

  const updatedWorkflow = await storeLoadById(
    executionContext,
    executionUser,
    workflowDefinitionEntity.id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity;
  // Validate consistency after update
  validateVersionConsistency(updatedWorkflow);

  addWorkflowPublishCount();
  if (scope === StatusScope.RequestAccess) {
    addWorkflowRequestAccessPublishCount();
  }

  const entitySettingWithWorkflow = entitySetting as BasicStoreEntityEntitySetting;
  return {
    id: entitySettingWithWorkflow.id,
    workflow_id: definitionId,
    target_type: entitySettingWithWorkflow.target_type,
    errors: [],
    published: true,
  } as EntitySettingWithWorkflowResponse;
};

/**
 * Restore the workflow draft to match the currently published version.
 * Clears draft_version so getWorkflowDefinition(allowDraft: true) falls back to published_version.
 */
export const restorePublishedWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope = StatusScope.Global,
): Promise<EntitySettingWithWorkflowResponse> => {
  assertScopeAllowed(entityType, scope);
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  const definitionId = resolveScopedDefinitionId(entitySetting, scope);
  if (!definitionId) {
    throw FunctionalError('No workflow definition found', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    definitionId,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: definitionId });
  }

  if (!workflowDefinitionEntity.published_version) {
    throw FunctionalError('No published version to restore', { entityType });
  }

  // Clearing draft_version causes getWorkflowDefinition(allowDraft: true) to fall back to
  // published_version, effectively restoring the graph to the last published state.
  await updateAttribute(
    executionContext,
    executionUser,
    workflowDefinitionEntity.id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
    [{ key: 'draft_version', value: [] }],
  );

  const entitySettingWithWorkflow = entitySetting as BasicStoreEntityEntitySetting;
  return {
    id: entitySettingWithWorkflow.id,
    workflow_id: definitionId,
    target_type: entitySettingWithWorkflow.target_type,
    errors: [],
    published: true,
  } as EntitySettingWithWorkflowResponse;
};

/**
 * Per-process, per-entity rate limit for read-repair checks, so a page of repeated reads for
 * the same entity doesn't re-run the mapped-Status lookup (nor a repair write) on every read.
 * Bounded LRU with TTL: entries expire after the window and memory stays capped.
 * Known limitation: this cache is per-process, so a multi-node deployment can still perform
 * one redundant repair per node within the TTL window — acceptable since repairs are
 * idempotent no-ops once consistent.
 */
const READ_REPAIR_RATE_LIMIT_TTL_MS = 5000;
const READ_REPAIR_RATE_LIMIT_MAX_ENTRIES = 10000;
const readRepairLastAttemptByEntity = new LRUCache<string, true>({ max: READ_REPAIR_RATE_LIMIT_MAX_ENTRIES, ttl: READ_REPAIR_RATE_LIMIT_TTL_MS });

// An external sync waits at most this long for the workflow mutation lock.
const EXTERNAL_SYNC_WINDOW_MS = conf.get('app:concurrency:retry_count') * (conf.get('app:concurrency:retry_delay') + conf.get('app:concurrency:retry_jitter')) + 5000;

// A Status written after the last workflow change may still be waiting for its sync: never revert it.
const isExternalSyncInFlight = (entity: BasicStoreEntity, instanceEntity: WorkflowInstanceStoreEntity): boolean => {
  const updatedAt = Date.parse(entity.updated_at as unknown as string);
  const lastChangeAt = Date.parse(parseWorkflowHistory(instanceEntity).at(-1)?.timestamp ?? '');
  return updatedAt > lastChangeAt && Date.now() - updatedAt < EXTERNAL_SYNC_WINDOW_MS;
};

/** Test-only: clears the read-repair rate-limit cache so tests can exercise it from a clean state. */
export const __resetReadRepairRateLimitForTest = (): void => {
  readRepairLastAttemptByEntity.clear();
};

/**
 * Get workflow instance for an entity, with live pending transition data.
 */
export const getWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<any> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return null;
  }
  // With ENTITIES_WORKFLOW disabled, the legacy x_opencti_workflow_id is the source of truth:
  // no instance must be exposed, backfilled, or used to read-repair (it would revert edits).
  if (entity.entity_type !== 'DraftWorkspace' && !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
    return null;
  }

  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const resolved = await resolveEntityDefinition(context, user, entity, entitySetting);
  const { definitionData } = resolved;
  if (!definitionData) {
    return null;
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  let instanceEntity = resolved.instanceEntity;
  if (!instanceEntity) {
    // Lazy backfill: a pre-existing entity created before this feature has no WorkflowInstance
    // row yet. Create one now, under the system identity (never the reading caller's), so
    // future reads/reconciliation have a real instance to work with. A failed backfill write
    // must not fail this read — fall back to the synthesized in-memory placeholder below.
    try {
      // `ensureWorkflowInstance`/`findWorkflowInstanceEntity` derive their execution identity
      // from `context.user` (via `bypassDraftContext`), not from a separately-passed user
      // argument — so the WORKFLOW_MANAGER_USER identity must be set on the context itself.
      const executionContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };
      instanceEntity = await ensureWorkflowInstance(executionContext, WORKFLOW_MANAGER_USER, entity, definitionData, resolved);
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Failed to lazily backfill WorkflowInstance for entity, falling back to synthesized instance', { cause: error, entityId: effectiveEntityId });
    }
  }
  const currentState = instanceEntity?.currentState ?? resolveSuppliedStatus(definitionData, resolved.suppliedStatus) ?? definitionData.initialState;

  // Read-repair: correct `x_opencti_workflow_id` divergence from `currentState`. Never runs
  // under the reading caller's identity, never fails/delays the read on error, and is
  // rate-limited per entity so repeated reads don't repeatedly re-write an already-consistent field.
  if (instanceEntity && currentState && !booleanConf('workflow:disable_read_repair', false)) {
    if (!readRepairLastAttemptByEntity.has(effectiveEntityId)) {
      // Record the attempt before checking, whatever the outcome, so consistent entities are
      // not re-queried on every read within the window.
      readRepairLastAttemptByEntity.set(effectiveEntityId, true);
      try {
        const scope = resolveProjectionScope(instanceEntity.scope);
        const repairContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };
        const needsRepair = async (repairEntity: BasicStoreEntity, repairInstance: WorkflowInstanceStoreEntity) => {
          const entityStatusId = repairEntity.x_opencti_workflow_id;
          if (entityStatusId && findKeptExternalStatusId(repairInstance) === entityStatusId) return false;
          if (isExternalSyncInFlight(repairEntity, repairInstance)) return false;
          const expectedStatusId = await resolveMappedStatusId(repairContext, WORKFLOW_MANAGER_USER, entity.entity_type, scope, repairInstance.currentState);
          return !!expectedStatusId && entityStatusId !== expectedStatusId;
        };
        if (await needsRepair(entity as BasicStoreEntity, instanceEntity)) {
          // Never repair under a running workflow mutation or external sync: it owns the Status.
          const lock = await lockResources([`workflow-mutation-${effectiveEntityId}`], { retryCount: 0 }).catch(() => null);
          if (lock) {
            try {
              // Re-read under the lock: a write may have landed since the first read.
              const lockedEntity = await storeLoadById<BasicStoreEntity>(repairContext, WORKFLOW_MANAGER_USER, effectiveEntityId, entity.entity_type);
              const lockedInstance = await findWorkflowInstanceEntity(repairContext, WORKFLOW_MANAGER_USER, effectiveEntityId);
              if (lockedEntity && lockedInstance && await needsRepair(lockedEntity, lockedInstance)) {
                await projectWorkflowState(repairContext, WORKFLOW_MANAGER_USER, lockedEntity, lockedInstance.currentState, scope);
                logApp.info('[OPENCTI-MODULE] Repaired x_opencti_workflow_id divergence from WorkflowInstance.currentState', { entityId: effectiveEntityId, entityType: entity.entity_type, currentState: lockedInstance.currentState });
              }
            } finally {
              await lock.unlock();
            }
          }
        }
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Failed to read-repair x_opencti_workflow_id, returning unrepaired instance', { cause: error, entityId: effectiveEntityId });
      }
    }
  }

  // Pass entitySetting and definitionData to avoid redundant lookups in getAllowedTransitions
  const statuses = await findStatusesByType(bypassDraftContext(context), bypassDraftUser(user), entity.entity_type);
  const { scope } = resolved;
  const currentStatus = statuses.find((status) => status.scope === scope && status.template_id === currentState) ?? null;
  const allowedTransitions = await getAllowedTransitions(context, user, entityId, { entity, entitySetting, definitionData, instanceEntity, statuses });
  const id = instanceEntity?.internal_id ?? instanceEntity?.id ?? `initial-${effectiveEntityId}`;

  // Parse pending transition and enrich with live Work data
  let pendingTransitionData: WorkflowPendingTransition | null = null;
  if (instanceEntity?.pendingTransition) {
    try {
      const raw: WorkflowPendingTransition = typeof instanceEntity.pendingTransition === 'string'
        ? JSON.parse(instanceEntity.pendingTransition)
        : instanceEntity.pendingTransition;

      // Enrich each slot with live BackgroundTask + Work entity data
      const enrichedSlots = await Promise.all(
        raw.asyncActions.map(async (slot) => {
          if (!slot.workId) return slot;
          const workEntity = await storeLoadById<any>(context, user, slot.workId, 'Work', { indices: [READ_INDEX_HISTORY] }).catch(() => null);
          if (!workEntity) return slot;
          // The BackgroundTask has task_expected_number (set at creation = ids.length)
          // and task_processed_number (updated per iteration by the task manager).
          // These are more reliable than Work's import_expected_number (which starts at 0
          // in Redis and is only updated in ES after the task manager runs).
          let processedCount = 0;
          let expectedCount = 0;
          const backgroundTaskId = workEntity.background_task_id;
          if (backgroundTaskId) {
            const bgTask = await storeLoadById<any>(context, user, backgroundTaskId, 'BackgroundTask').catch(() => null);
            if (bgTask) {
              expectedCount = bgTask.task_expected_number ?? 0;
              processedCount = bgTask.task_processed_number ?? 0;
            }
          }
          return {
            ...slot,
            processedCount,
            expectedCount,
            startedAt: workEntity.received_time ?? null,
            lastActivityAt: workEntity.updated_at ?? null,
            errors: (workEntity.errors ?? []).slice(0, 100),
            workStatus: workEntity.status ?? null,
          };
        }),
      );
      pendingTransitionData = { ...raw, asyncActions: enrichedSlots };
    } catch {
      // Malformed JSON — surface as null, admin can use clearWorkflowPendingState
    }
  }

  return {
    id,
    internal_id: id,
    __typename: 'WorkflowInstance',
    currentState: currentState || '',
    currentStatus,
    allowedTransitions,
    history: JSON.parse(instanceEntity?.history || '[]'),
    pendingStatus: instanceEntity?.pendingStatus ?? null,
    pendingError: instanceEntity?.pendingError ?? null,
    pendingTransition: pendingTransitionData,
    scope: instanceEntity ? (instanceEntity.scope ?? 'standard') : resolved.scope,
  };
};

type TransitionInputRequirements = {
  comment?: string | null;
  requiresShareOrganizationInput?: boolean;
  requiresUnshareOrganizationInput?: boolean;
};

// Organizations a share/unshare action configured without any must receive at runtime
const getMissingOrganizationInput = (requirements: TransitionInputRequirements, runtimeParams: Record<string, unknown>) => {
  for (const [key, required] of [
    ['shareOrganizationIds', requirements.requiresShareOrganizationInput],
    ['unshareOrganizationIds', requirements.requiresUnshareOrganizationInput],
  ] as const) {
    const ids = runtimeParams[key];
    if (required && (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => typeof id !== 'string' || !id.trim()))) {
      return `${key} must contain at least one organization ID`;
    }
  }
  return undefined;
};

// Inputs the triggering user must give: the organizations, and a required comment unless the user can bypass mandatory fields
const getMissingTransitionInput = (user: AuthUser, transition: TransitionInputRequirements, comment?: string, runtimeParams: Record<string, unknown> = {}) => {
  if (transition.comment === 'required' && !comment?.trim() && !isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS)) {
    return 'A comment is required for this transition';
  }
  return getMissingOrganizationInput(transition, runtimeParams);
};

const toAllowedTransition = (
  transition: ReturnType<ReturnType<typeof WorkflowFactory.createDefinition>['getTransitions']>[number],
  statuses: BasicWorkflowStatus[],
  scope: StatusScope,
  definitionData: Pick<WorkflowDefinitionResponse, 'states'>,
  // A plain RFI on a request access status carries no request: none of its transitions decides one
  decidesRequest = scope === StatusScope.RequestAccess,
) => ({
  event: transition.event,
  toState: transition.to ?? null,
  toStatus: statuses.find((status) => status.scope === scope && status.template_id === transition.to) ?? null,
  comment: transition.comment,
  closingReason: transition.closingReason,
  actions: transition.actionTypes || [],
  requiresShareOrganizationInput: transition.requiresShareOrganizationInput ?? false,
  requiresUnshareOrganizationInput: transition.requiresUnshareOrganizationInput ?? false,
  requestAccessOutcome: (decidesRequest ? findStateOutcome(definitionData, transition.to) : undefined) ?? null,
});

type TransitionRefusal = 'forbidden' | 'noLiveEntity' | 'confidence';

const TRANSITION_REFUSAL_REASONS: Record<Exclude<TransitionRefusal, 'forbidden'>, string> = {
  noLiveEntity: 'This entity has no live version to write the workflow status on',
  confidence: 'Your confidence level is too low to update this entity',
};

// A transition writes the new status with the user's rights, on the live entity even from a draft:
// refuse it when that write would fail, instead of moving the instance without the status.
const getTransitionRefusal = async (context: AuthContext, user: AuthUser, entityId: string, entity: BasicStoreCommon): Promise<TransitionRefusal | null> => {
  // View access alone isn't enough to trigger a transition (e.g. a user restricted by an authorized-members group)
  if (!validateUserAccessOperation(user, entity, AccessOperation.EDIT)) {
    return 'forbidden';
  }
  let statusWriteTarget = entity;
  if (getDraftContext(context, user)) {
    // From a draft, the user also needs edit access to the live entity, which must exist
    const liveEntity = await storeLoadById(bypassDraftContext(context), bypassDraftUser(user), entityId, 'Basic-Object');
    if (!liveEntity) {
      // The draft copy tells which case it is: an entity created in the draft has no live version,
      // any other one exists live but is hidden from the user
      return entity.draft_change?.draft_operation === DRAFT_OPERATION_CREATE ? 'noLiveEntity' : 'forbidden';
    }
    if (!validateUserAccessOperation(user, liveEntity, AccessOperation.EDIT)) {
      return 'forbidden';
    }
    statusWriteTarget = liveEntity;
  }
  return controlUserConfidenceAgainstElement(user, statusWriteTarget, true) ? null : 'confidence';
};

/**
 * Get allowed transitions for an entity.
 */
export const getAllowedTransitions = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  options?: {
    entity?: BasicStoreCommon;
    entitySetting?: BasicStoreEntityEntitySetting;
    definitionData?: WorkflowDefinitionResponse | null;
    instanceEntity?: WorkflowInstanceStoreEntity | null;
    statuses?: BasicWorkflowStatus[];
    // State of an entity whose instance is not created yet, when its status maps to another state than the initial one
    currentState?: string;
  },
): Promise<Array<{
  event: string;
  toState: string | null;
  toStatus: BasicWorkflowStatus | null;
  comment?: string;
  closingReason?: string;
  actions: string[];
  requiresShareOrganizationInput: boolean;
  requiresUnshareOrganizationInput: boolean;
  requestAccessOutcome: RequestAccessOutcome | null;
}>> => {
  const entity = options?.entity ?? await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return [];
  }

  const entitySetting = options?.entitySetting ?? await getWorkflowConfig(context, user, entity.entity_type);
  if (!hasWorkflowDefinition(entitySetting)) {
    return [];
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = options?.instanceEntity ?? await findWorkflowInstanceEntity(context, user, effectiveEntityId);
  const suppliedStatus = instanceEntity ? null : await findStatusInCache(context, (entity as { x_opencti_workflow_id?: string }).x_opencti_workflow_id);
  const { scope, definitionData } = options?.definitionData
    ? { scope: resolveProjectionScope(instanceEntity?.scope ?? suppliedStatus?.scope), definitionData: options.definitionData }
    : await resolveInstanceDefinition(context, user, entitySetting, instanceEntity, suppliedStatus);
  // A supplied definition is only valid for the scope it belongs to: it is never read with the statuses of another
  if (!definitionData || definitionData.id !== resolveScopedDefinitionId(entitySetting, scope)) {
    return [];
  }
  if (instanceEntity?.completed) {
    return [];
  }
  // Checked after the cheap checks: from a draft, it loads the live entity
  if (await getTransitionRefusal(context, user, entityId, entity)) {
    return [];
  }
  // Without instance yet, the entity is in the state its instance will be created at
  const currentStateId = instanceEntity?.currentState ?? options?.currentState ?? resolveSuppliedStatus(definitionData, suppliedStatus) ?? definitionData.initialState;

  const definition = WorkflowFactory.createDefinition(definitionData);
  const effectiveStateId = currentStateId || definition.getInitialState();
  if (!effectiveStateId || !definition.hasState(effectiveStateId)) {
    return [];
  }

  const transitions = definition.getTransitions(effectiveStateId);
  const statuses = options?.statuses ?? await findStatusesByType(bypassDraftContext(context), bypassDraftUser(user), entity.entity_type);

  // Pre-evaluate conditions against the requesting user so the frontend only
  // sees transitions the current user is actually allowed to trigger.
  // Entity attribute conditions read the live entity, like triggerWorkflowEvent does: workflow state is live only.
  const conditionContext = { entity, user, triggeringUser: user, context: bypassDraftContext(context) };
  const resolvedTransitions = (await Promise.all(
    transitions.map(async (transition) => {
      for (const condition of (transition.conditions ?? [])) {
        const passes = await condition(conditionContext as any);
        if (!passes) return null;
      }
      return toAllowedTransition(transition, statuses, scope, definitionData, scope === StatusScope.RequestAccess && hasRequestAccess(entity));
    }),
  )).filter((t): t is NonNullable<typeof t> => t !== null);

  return resolvedTransitions;
};

type AllowedTransition = Awaited<ReturnType<typeof getAllowedTransitions>>[number];

// The mass update collects these inputs once for every entity, so they must be the same for all of them
const hasSameInputRequirements = (transition: AllowedTransition, other: AllowedTransition) => {
  return (transition.comment ?? 'disabled') === (other.comment ?? 'disabled')
    && (transition.closingReason ?? 'disabled') === (other.closingReason ?? 'disabled')
    && transition.requiresShareOrganizationInput === other.requiresShareOrganizationInput
    && transition.requiresUnshareOrganizationInput === other.requiresUnshareOrganizationInput;
};

const keepCommonTransitions = (transitionLists: AllowedTransition[][]): AllowedTransition[] => {
  if (transitionLists.length === 0) return [];
  const [first, ...others] = transitionLists;
  return first.filter((transition) => others.every((list) => list.some((other) => {
    return other.event === transition.event && other.toState === transition.toState && hasSameInputRequirements(transition, other);
  })));
};

/**
 * The state that getWorkflowInstance shows for an entity of this type with no WorkflowInstance yet.
 * Null when the type has no published workflow, so no entity of it shows a workflow status;
 * initialState is null when the workflow has no single initial state ('*').
 */
export const getWorkflowDefaultState = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<{ initialState: string | null } | null> => {
  if (entityType !== 'DraftWorkspace' && !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) return null;
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const definitionData = await getDefinitionData(context, user, entitySetting);
  if (!definitionData) return null;
  const { initialState } = definitionData;
  return { initialState: initialState && initialState !== '*' ? initialState : null };
};

/**
 * Transitions that every targeted entity can take, for a mass transition. A selection is checked
 * entity by entity, conditions included. A filter (select all) is checked from the statuses found
 * under it: entities without status are in the initial state, and conditions are only checked when
 * the transition runs. A transition that needs a comment, a closing reason or organizations gets
 * them from the mass update, the same for every entity: it is only offered when every state asks for
 * the same inputs.
 */
export const getMassWorkflowTransitions = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  target: { entityIds?: string[] | null; filters?: string | null; search?: string | null; excludedIds?: string[] | null },
  scope: StatusScope = StatusScope.Global,
): Promise<AllowedTransition[]> => {
  if (entityType !== 'DraftWorkspace' && !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) return [];
  assertScopeAllowed(entityType, scope);
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const definitionData = await getDefinitionData(context, user, entitySetting, false, scope);
  if (!definitionData) return [];
  const statuses = await findStatusesByType(bypassDraftContext(context), bypassDraftUser(user), entityType);
  if (target.entityIds) {
    // An entity whose instance is of another scope has no transition in this one: getAllowedTransitions
    // refuses to read the supplied definition for it.
    const transitionLists = await BluePromise.map(target.entityIds, (entityId) => {
      return getAllowedTransitions(context, user, entityId, { entitySetting, definitionData, statuses });
    }, { concurrency: ES_MAX_CONCURRENCY });
    return keepCommonTransitions(transitionLists);
  }
  let filters = target.filters ? JSON.parse(target.filters) : undefined;
  if (target.excludedIds && target.excludedIds.length > 0) {
    filters = addFilter(filters, 'internal_id', target.excludedIds, 'not_eq', 'and');
  }
  const statusCounts = await elAggregationCount(context, user, READ_DATA_INDICES, {
    field: 'x_opencti_workflow_id',
    types: [entityType],
    filters,
    search: target.search || null,
    normalizeLabel: false,
  });
  const definition = WorkflowFactory.createDefinition(definitionData);
  const countedStatuses = statusCounts.map(({ label }) => statuses.find((status) => status.id === label));
  // An entity on a status of another scope has no transition in this one
  if (countedStatuses.some((status) => status && status.scope !== scope)) return [];
  const states = new Set(countedStatuses.map((status) => status?.template_id ?? definitionData.initialState));
  return keepCommonTransitions([...states].map((state) => {
    return definition.getTransitions(state).map((transition) => toAllowedTransition(transition, statuses, scope, definitionData));
  }));
};

// The entity is read before the lock: a reason written meanwhile only shows once the entity is read again
const isClosingReasonLostOnStoredEntity = async (context: AuthContext, user: AuthUser, closingReason: string | null | undefined, entity: BasicStoreEntity) => {
  if (closingReason !== null) return isClosingReasonLost(closingReason, entity);
  try {
    return isClosingReasonLost(null, await storeLoadById<BasicStoreEntity>(context, user, entity.internal_id, 'Basic-Object'));
  } catch {
    return true;
  }
};

const isClosingReasonMode = (mode: string | undefined) => mode === 'allowed' || mode === 'required';

// A closing reason is only asked on the way into a final state (no transition leaves it), and kept while the entity
// stays in one: any move to a state it can leave clears it.
// It does not look at the stored reason: the entity may be read before the lock, and clearing an empty one changes nothing.
// Nor at the transitions asking for one: a workflow that stopped asking must still clear a reason given before.
// Entity types without the attribute (outside domain objects) never carry one.
const clearsClosingReason = (
  entityType: string,
  transitions: Pick<WorkflowSerializedTransition, 'from'>[] | undefined,
  fromState: string,
  toState: string,
) => {
  return fromState !== toState
    && !!schemaAttributesDefinition.getAttribute(entityType, X_CLOSING_REASON)
    && findStatesWithOutgoingTransitions(transitions ?? []).has(toState);
};

const resolveTransitionClosingReason = (
  user: AuthUser,
  mode: string | undefined,
  closingReason: string | undefined,
  clears: boolean,
): { closingReason: string | null | undefined } | { error: string } => {
  const value = closingReason?.trim() || null;
  if (!isClosingReasonMode(mode)) {
    if (value) return { error: 'Closing reason is not enabled for this transition' };
    return { closingReason: clears ? null : undefined };
  }
  if (mode === 'required' && !value && !isUserHasCapability(user, KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS)) {
    return { error: 'A closing reason is required for this transition' };
  }
  return { closingReason: value };
};

// Vocabulary ids ignore case: the stored value takes the vocabulary spelling so usages, renames and filters match it
// An id of a vocabulary from another category is not a closing reason
const findClosingReasonVocabularyName = async (context: AuthContext, value: string): Promise<string | undefined> => {
  const vocabularyId = idVocabulary(value, VocabularyCategory.ClosingReasonOv);
  const vocabulary = await storeLoadById<BasicStoreEntityVocabulary>(context, SYSTEM_USER, vocabularyId, ENTITY_TYPE_VOCABULARY);
  return vocabulary?.category === VocabularyCategory.ClosingReasonOv ? vocabulary.name : undefined;
};

/**
 * Trigger a workflow event on an entity.
 * This is the main entry point for the backend logic.
 *
 * @param context The auth context
 * @param user The auth user
 * @param entityId The ID of the entity to trigger the event on
 * @param eventName The name of the event to trigger
 * @param comment Optional comment entered by the user when performing the transition
 * @param runtimeParams Optional runtime parameters (e.g. organizationIds for share actions). Persisted for retry.
 * @param closingReason Optional closing reason, accepted only when the transition enables it
 * @param options.fromState Refuses the event unless the entity is still in this state once locked
 * @returns {Promise<TriggerResult>} The result of the trigger
 */
export const triggerWorkflowEvent = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  eventName: string,
  comment?: string,
  runtimeParams: Record<string, unknown> = {},
  closingReason?: string,
  options: { fromState?: string } = {},
): Promise<TriggerResult> => {
  // 1. Fetch the entity
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    throw FunctionalError('Entity not found', { entityId });
  }

  // 2. Fetch its EntitySetting to get the workflow configuration
  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const notConfigured: TriggerResult = {
    success: false,
    reason: `Workflows are not configured for entity type: ${entity.entity_type}`,
  };
  if (!hasWorkflowDefinition(entitySetting)) {
    return notConfigured;
  }

  // Same refusal as getAllowedTransitions, which only hides transitions from the UI:
  // a user can still call this mutation directly.
  const refusal = await getTransitionRefusal(context, user, entityId, entity);
  if (refusal === 'forbidden') {
    throw ForbiddenAccess();
  }
  if (refusal) {
    return { success: false, reason: TRANSITION_REFUSAL_REASONS[refusal] };
  }

  let lock;
  try {
    lock = await lockResources([`workflow-mutation-${entity.internal_id || entity.id}`]);
    const executionContext = bypassDraftContext(context);
    const executionUser = bypassDraftUser(user);

    const resolved = await resolveEntityDefinition(executionContext, executionUser, entity, entitySetting);
    const { definitionData } = resolved;
    if (!definitionData) {
      return notConfigured;
    }

    const instanceEntity = await ensureWorkflowInstance(executionContext, executionUser, entity, definitionData, resolved);

    if (instanceEntity.completed) {
      return { success: false, reason: 'Workflow has already completed' };
    }

    // 3. Lock check: reject new events while a transition is already pending
    if (instanceEntity.pendingStatus === 'pending') {
      return {
        success: false,
        reason: 'A workflow transition is already pending for this entity. Wait for it to complete, retry the failed action, or ask an admin to clear the pending state.',
      };
    }

    const currentStateId = instanceEntity.currentState;
    // An event chosen for a given state must not run under the same name from another one
    if (options.fromState && currentStateId !== options.fromState) {
      return { success: false, reason: 'The workflow state changed before the transition ran, retry from the current state', entity };
    }
    const definition = WorkflowFactory.createDefinition(definitionData);
    const targetTransition = definitionData.transitions?.find((t: any) => {
      const fromStates = Array.isArray(t.from) ? t.from : [t.from];
      return fromStates.includes(currentStateId) && t.event === eventName;
    });
    const clears = !!targetTransition?.to && clearsClosingReason(entity.entity_type, definitionData.transitions, currentStateId, targetTransition.to);
    // The reason is written to the live entity: draft-only capabilities cannot skip a required one.
    // Without a transition for this event, the engine rejects the event itself: the reason is not checked.
    const resolvedClosingReason: ReturnType<typeof resolveTransitionClosingReason> = targetTransition
      ? resolveTransitionClosingReason(executionUser, targetTransition.closingReason, closingReason, clears)
      : { closingReason: undefined };
    if ('error' in resolvedClosingReason) {
      return { success: false, reason: resolvedClosingReason.error };
    }
    if (resolvedClosingReason.closingReason) {
      const vocabularyName = await findClosingReasonVocabularyName(bypassDraftContext(context), resolvedClosingReason.closingReason);
      if (!vocabularyName) {
        return { success: false, reason: 'Closing reason must be a value of the closing reason vocabulary' };
      }
      resolvedClosingReason.closingReason = vocabularyName;
    }

    // 4. Inject createListTask and instance metadata into context for asyncBulkAction.
    // When the workflow entity is a DraftWorkspace, pre-query only the STIX entities that
    // belong to this specific draft (using the dedicated draft index + draft_ids filter).
    const draftEntityIds: string[] = [];
    if ((entity as any).entity_type === 'DraftWorkspace') {
      const draftId = (entity as any).internal_id;
      const draftCtx = { ...executionContext, draft_context: draftId };
      const draftFilter = {
        mode: FilterMode.And,
        filters: [{ key: ['draft_ids'], values: [draftId] }],
        filterGroups: [],
      };
      const draftItems = await fullEntitiesList<any>(draftCtx, executionUser, ['Stix-Core-Object'], {
        indices: [READ_INDEX_DRAFT_OBJECTS],
        filters: draftFilter,
      });
      // Exclude update_linked entities — these are entities indirectly pulled into the draft
      // (e.g. organizations referenced by new sharing relations) and should not be targeted
      // by subsequent async actions like org sharing/unsharing.
      draftEntityIds.push(...draftItems
        .filter((item: any) => item.draft_change?.draft_operation !== DRAFT_OPERATION_UPDATE_LINKED)
        .map((item: any) => item.internal_id)
        .filter(Boolean));
    }

    const workflowContext = {
      entity,
      user: WORKFLOW_MANAGER_USER,
      triggeringUser: executionUser,
      context: executionContext,
      runtimeParams,
      __createListTask: createListTask,
      __workflowInstanceId: instanceEntity.internal_id || instanceEntity.id,
      __draftEntityIds: draftEntityIds,
    };

    // 5. Reject a transition whose required inputs are missing, before any action runs
    const transition = definition.getTransitions(currentStateId).find((t) => t.event === eventName);
    const missingInput = transition && getMissingTransitionInput(user, transition, comment, runtimeParams);
    if (missingInput) {
      return { success: false, reason: missingInput, entity };
    }
    // Entering an outcome state decides the access request, which takes the request approver rights of the actual caller.
    // A plain RFI on a request access status carries no request to decide, like resolveRequestAccessWorkflowState
    const decidesRequest = resolved.scope === StatusScope.RequestAccess && hasRequestAccess(entity);
    const requestAccessOutcome = decidesRequest ? findStateOutcome(definitionData, transition?.to) : undefined;
    if (requestAccessOutcome) {
      await assertCanEnterRequestAccessOutcome(context, user, entity as BasicStoreEntityCaseRfi);
      assertNoFailedRequestAccessShare(instanceEntity, eventName, transition?.to);
    }

    // 6. Create instance and trigger the event
    const instance = WorkflowFactory.getInstance(definitionData, definition, currentStateId || '', workflowContext);
    const result = await instance.trigger(eventName);

    if (!result.success) {
      // The engine names the state by its status template id, unreadable in task errors and notifications
      if (!transition) {
        const statusTemplate = await storeLoadById<BasicStoreEntity>(executionContext, executionUser, currentStateId, ENTITY_TYPE_STATUS_TEMPLATE);
        const reason = `Transition '${eventName}' is not available from status '${statusTemplate?.name ?? currentStateId}'`;
        return { ...result, reason, entity };
      }
      return { ...result, entity };
    }

    const instanceId = instanceEntity.internal_id || instanceEntity.id;

    // 6a. Async transition: persist pendingTransition, do NOT advance state
    if (result.executionStatus === 'pending' && result.asyncActionSlots && result.asyncActionSlots.length > 0) {
      // The action already generated stable slot IDs (identical to workflow_action_id on the BackgroundTask)
      const rawSlots: AsyncActionSlot[] = result.asyncActionSlots.map((rawSlot: any) => ({
        id: rawSlot.id,
        workId: rawSlot.workId,
        type: rawSlot.type,
        status: 'pending' as const,
      }));

      // An onEnter action suspended the transition: the transition actions and the onEnter actions before it already ran.
      const completedOnEnterActions = result.completedOnEnterActions;
      // fallback on actions if syncActions not explicitly defined on transition (legacy support)
      const serializedTransitions: WorkflowActionConfig[] = completedOnEnterActions === undefined ? (targetTransition?.syncActions ?? []) : [];

      // Collect the onEnter actions of the target state so phase 2 can replay them.
      const toStateId = targetTransition?.to ?? instance.getCurrentState();
      // A null `to` only completes the workflow when paired with `validateDraft` (see
      // workflow-validation.ts) - otherwise it's a stale orphaned reference (e.g. a status
      // deleted after this definition was published, before that validation gate existed).
      const completesWorkflow = targetTransition != null
        && targetTransition.to == null
        && serializedTransitions.some((action) => action.type === 'validateDraft');
      const targetStateDef = completesWorkflow ? undefined : definitionData.states?.find((s: any) => s.statusId === toStateId);
      const serializedOnEnterActions: WorkflowActionConfig[] = (targetStateDef?.onEnter ?? []).slice(completedOnEnterActions ?? 0);

      const pendingTransition: WorkflowPendingTransition = {
        event: eventName,
        toState: toStateId,
        ...(completesWorkflow ? { completesWorkflow: true } : {}),
        triggeredBy: user.id,
        triggeredAt: new Date().toISOString(),
        runtimeParams,
        ...(comment ? { comment } : {}),
        ...(resolvedClosingReason.closingReason !== undefined ? { closingReason: resolvedClosingReason.closingReason } : {}),
        asyncActions: rawSlots,
        syncActions: serializedTransitions,
        ...(serializedOnEnterActions.length > 0 ? { onEnterActions: serializedOnEnterActions } : {}),
        ...(requestAccessOutcome ? { requestAccessOutcome } : {}),
      };

      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['pending'] },
        { key: 'pendingError', value: [null] },
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
      ]);

      await lock.unlock();
      lock = undefined;
      const workflowInstance = await getWorkflowInstance(context, user, entityId);
      return {
        success: true,
        executionStatus: 'pending',
        instance: workflowInstance,
        entity,
      };
    }

    // 6b. Sync-only transition: state already advanced by engine — persist the new state
    const newState = instance.getCurrentState();
    let history: any[];
    try {
      history = JSON.parse(instanceEntity.history || '[]');
    } catch {
      history = [];
    }

    history = appendWorkflowHistoryEntry(history, {
      state: newState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: eventName,
      ...(result.workflowCompleted ? { completed: true } : {}),
      ...(comment ? { comment } : {}),
      ...(resolvedClosingReason.closingReason ? { closing_reason: resolvedClosingReason.closingReason } : {}),
    });

    // A retry of the failed transition that now completes at once ends that failure, before the request is decided below
    const failedTransition = instanceEntity.pendingStatus === 'error' ? parsePendingTransition(instanceEntity) : undefined;
    const retriedFailedTransition = !!failedTransition && failedTransition.event === eventName && failedTransition.toState === newState;
    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'currentState', value: [newState] },
      { key: 'history', value: [JSON.stringify(history)] },
      ...(result.workflowCompleted ? [{ key: 'completed', value: [true] }] : []),
      ...(retriedFailedTransition ? [{ key: 'pendingStatus', value: [null] }, { key: 'pendingTransition', value: [null] }] : []),
      // The transition re-projects the status, ending any kept external write.
      ...(instanceEntity.pendingStatus && !retriedFailedTransition ? [] : [{ key: 'pendingError', value: [null] }]),
    ]);

    // Keep the legacy `x_opencti_workflow_id` in sync with the new state.
    // `projectWorkflowState` never throws (best-effort, logs and skips on failure).
    const scope = resolveProjectionScope(instanceEntity.scope);
    const projected = await projectWorkflowState(executionContext, executionUser, entity as BasicStoreEntity, newState, scope, resolvedClosingReason.closingReason);
    if (!projected && await isClosingReasonLostOnStoredEntity(executionContext, executionUser, resolvedClosingReason.closingReason, entity as BasicStoreEntity)) {
      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingError', value: [closingReasonNotWrittenError(resolvedClosingReason.closingReason ?? null)] },
      ]);
    }
    if (requestAccessOutcome) {
      await recordRequestAccessDecision(executionContext, executionUser, entity as BasicStoreEntityCaseRfi, requestAccessOutcome, instanceId);
    }

    await lock.unlock();
    lock = undefined;
    const workflowInstance = await getWorkflowInstance(context, user, entityId);
    // Notify assignees and participants when a non-empty comment was provided
    if (comment?.trim()) {
      await notifyWorkflowTransitionComment(executionContext, entity as BasicStoreEntity, eventName, comment, user.id);
    }

    return { success: true, newState, executionStatus: 'completed', instance: workflowInstance, entity };
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      reason: `Workflow execution failed: ${reason}`,
    };
  } finally {
    await lock?.unlock();
  }
};

const loadWorkflowBypass = async (context: AuthContext, user: AuthUser, entityId: string) => {
  if (!isBypassUser(user)) throw FunctionalError('BYPASS permission is required');
  const entity = await storeLoadById<BasicStoreEntity>(context, user, entityId, 'Basic-Object');
  if (!entity) throw FunctionalError('Entity not found', { entityId });
  if (entity.entity_type !== 'DraftWorkspace' && !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
    throw FunctionalError('ENTITIES_WORKFLOW is disabled');
  }
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const entitySetting = await getWorkflowConfig(executionContext, executionUser, entity.entity_type);
  const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, entity.internal_id || entity.id);
  const suppliedStatus = !instanceEntity && entity.x_opencti_workflow_id
    ? await storeLoadById<BasicWorkflowStatus>(executionContext, executionUser, entity.x_opencti_workflow_id, ENTITY_TYPE_STATUS)
    : null;
  const { scope, definitionData } = await resolveInstanceDefinition(executionContext, executionUser, entitySetting, instanceEntity, suppliedStatus);
  // Only a request on the published request-access workflow can be bypassed: legacy requests keep their own flow
  const isRequestAccess = ('x_opencti_request_access' in entity && !!entity.x_opencti_request_access) || scope === StatusScope.RequestAccess;
  if (isRequestAccess && (scope !== StatusScope.RequestAccess || !await resolveRequestAccessWorkflowState(executionContext, entity))) {
    throw FunctionalError('RequestAccess workflow bypass is not supported');
  }
  // Without instance, the same state as transitions and allowedTransitions see
  const currentState = instanceEntity?.currentState ?? (definitionData ? resolveSuppliedStatus(definitionData, suppliedStatus) ?? definitionData.initialState : undefined);
  return { entity, definitionData, instanceEntity, suppliedStatus, currentState, scope, executionContext, executionUser };
};

const getWorkflowBypassRequirements = (definitionData: WorkflowDefinitionResponse, currentState: string | undefined, targetState: string) => {
  const onExit = definitionData.states?.find((state) => state.statusId === currentState)?.onExit ?? [];
  const onEnter = definitionData.states?.find((state) => state.statusId === targetState)?.onEnter ?? [];
  const actions = [...onExit, ...onEnter];
  const runtimeActions = actions.filter((action) => action.type === 'asyncBulkAction').flatMap((action) => {
    const params: { actions?: { type: string; context?: { values?: unknown[] } }[] } | undefined = typeof action.params === 'string'
      ? JSON.parse(action.params) : action.params;
    return (params?.actions ?? []).filter((innerAction) => !innerAction.context?.values?.length);
  });
  return {
    onExit,
    onEnter,
    requiresShareOrganizationInput: runtimeActions.some((action) => action.type === 'SHARE'),
    requiresUnshareOrganizationInput: runtimeActions.some((action) => action.type === 'UNSHARE'),
  };
};

// Statuses of the entity type and scope mapped to a state of the workflow, in workflow order
const findWorkflowMappedStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope,
  definitionData: WorkflowDefinitionResponse,
): Promise<BasicWorkflowStatus[]> => {
  const stateIds = Array.from(extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]));
  if (stateIds.length === 0) return [];
  const statuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [entityType] },
        { key: ['scope'], values: [scope] },
        { key: ['template_id'], values: stateIds },
      ],
      filterGroups: [],
    },
    orderBy: 'order',
    orderMode: OrderingMode.Asc,
  });
  return statuses.filter((status) => status.entity_type === ENTITY_TYPE_STATUS
    && status.type === entityType && status.scope === scope && stateIds.includes(status.template_id))
    .sort((left, right) => left.order - right.order);
};

export const getWorkflowBypassStatuses = async (context: AuthContext, user: AuthUser, entityId: string) => {
  const { entity, definitionData, currentState, scope, executionContext, executionUser } = await loadWorkflowBypass(context, user, entityId);
  if (!definitionData) return [];
  const statuses = await findWorkflowMappedStatuses(executionContext, executionUser, entity.entity_type, scope, definitionData);
  return statuses.map((status) => ({ status, ...getWorkflowBypassRequirements(definitionData, currentState, status.template_id) }));
};

/**
 * Statuses of the published workflow of an entity type, for a mass status update. Exposed to
 * knowledge editors, unlike `workflowDefinition`.
 */
export const getWorkflowStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  scope: StatusScope = StatusScope.Global,
): Promise<BasicWorkflowStatus[]> => {
  if (entityType !== 'DraftWorkspace' && !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) return [];
  const definitionData = await getWorkflowDefinition(context, user, entityType, false, scope);
  if (!definitionData) return [];
  return findWorkflowMappedStatuses(bypassDraftContext(context), bypassDraftUser(user), entityType, scope, definitionData);
};

const executeWorkflowBypass = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  targetStatusId: string,
  applyTransitionActions: boolean,
  comment?: string | null,
  runtimeParams: Record<string, unknown> = {},
): Promise<TriggerResult> => {
  const normalizedComment = comment?.trim() || undefined;
  if (normalizedComment && normalizedComment.length > COMMENT_MAX_LENGTH) throw FunctionalError(`Comment exceeds maximum allowed length of ${COMMENT_MAX_LENGTH} characters.`);
  const {
    entity, definitionData, instanceEntity: existingInstance, suppliedStatus, currentState, scope, executionContext, executionUser,
  } = await loadWorkflowBypass(context, user, entityId);
  if (!definitionData) return { success: false, reason: `Workflows are not configured for entity type: ${entity.entity_type}` };
  const targetStatus = await storeLoadById<BasicWorkflowStatus>(executionContext, executionUser, targetStatusId, ENTITY_TYPE_STATUS);
  if (!targetStatus || targetStatus.entity_type !== ENTITY_TYPE_STATUS || targetStatus.type !== entity.entity_type
    || targetStatus.scope !== scope || !extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]).has(targetStatus.template_id)
    || await resolveMappedStatusId(executionContext, executionUser, entity.entity_type, scope, targetStatus.template_id) !== targetStatusId) {
    return { success: false, reason: 'Target Status is not mapped to the published workflow for this entity type and scope' };
  }
  if (existingInstance?.pendingStatus === 'pending' || existingInstance?.pendingStatus === 'error') {
    return { success: false, reason: 'A workflow transition is pending or failed. Clear the pending state before bypassing.' };
  }
  // Already in the target status: nothing to run nor to record, so a playbook or a mass update cannot replay the actions
  if (currentState === targetStatus.template_id) {
    return { success: true, executionStatus: 'completed', newState: currentState, unchanged: true, entity };
  }
  if (applyTransitionActions) {
    const missingInput = getMissingOrganizationInput(getWorkflowBypassRequirements(definitionData, currentState, targetStatus.template_id), runtimeParams);
    if (missingInput) {
      return { success: false, reason: missingInput };
    }
  }
  const instanceEntity = await ensureWorkflowInstance(executionContext, executionUser, entity, definitionData, { instanceEntity: existingInstance, suppliedStatus, scope }, false);
  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  // A bypass decides a request only with actions; otherwise, and out of an outcome state, the request status just follows the state
  const enteredOutcome = scope === StatusScope.RequestAccess ? findStateOutcome(definitionData, targetStatus.template_id) : undefined;
  const leftOutcome = scope === StatusScope.RequestAccess ? findStateOutcome(definitionData, currentState) : undefined;
  const requestAccessOutcome = applyTransitionActions ? enteredOutcome : undefined;
  const requestAccessStatus = enteredOutcome ?? (leftOutcome ? 'NEW' : undefined);
  const pendingTransition: WorkflowPendingTransition = {
    event: 'event_bypass',
    toState: targetStatus.template_id,
    triggeredBy: user.id,
    triggeredAt: new Date().toISOString(),
    runtimeParams,
    ...(normalizedComment ? { comment: normalizedComment } : {}),
    ...(clearsClosingReason(entity.entity_type, definitionData.transitions, instanceEntity.currentState, targetStatus.template_id) ? { closingReason: null } : {}),
    asyncActions: [],
    syncActions: applyTransitionActions ? [
      ...(definitionData.states?.find((state) => state.statusId === instanceEntity.currentState)?.onExit ?? []),
      ...(definitionData.states?.find((state) => state.statusId === targetStatus.template_id)?.onEnter ?? []),
    ] : [],
    ...(requestAccessOutcome ? { requestAccessOutcome } : {}),
    ...(!requestAccessOutcome && requestAccessStatus === 'NEW' ? { requestAccessStatus } : {}),
  };
  try {
    const draftEntityIds: string[] = [];
    if (applyTransitionActions && entity.entity_type === 'DraftWorkspace') {
      const draftId = entity.internal_id || entity.id;
      const draftItems = await fullEntitiesList<BasicStoreEntity>({ ...executionContext, draft_context: draftId }, executionUser, ['Stix-Core-Object'], {
        indices: [READ_INDEX_DRAFT_OBJECTS],
        filters: { mode: FilterMode.And, filters: [{ key: ['draft_ids'], values: [draftId] }], filterGroups: [] },
      });
      draftEntityIds.push(...draftItems.filter((item) => item.draft_change?.draft_operation !== DRAFT_OPERATION_UPDATE_LINKED).map((item) => item.internal_id).filter(Boolean));
      pendingTransition.draftEntityIds = draftEntityIds;
    }
    if (pendingTransition.syncActions.length > 0) {
      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['pending'] },
        { key: 'pendingError', value: [null] },
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
      ]);
    }
    await runWorkflowBypassActions({
      entity,
      user: WORKFLOW_MANAGER_USER,
      triggeringUser: executionUser,
      context: executionContext,
      runtimeParams,
      __createListTask: createListTask,
      __workflowInstanceId: instanceId,
      __draftEntityIds: draftEntityIds,
    }, pendingTransition);
    if (pendingTransition.asyncActions.length > 0) {
      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['pending'] },
        { key: 'pendingError', value: [null] },
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
      ]);
      return { success: true, executionStatus: 'pending', entity };
    }
    let history;
    try {
      history = JSON.parse(instanceEntity.history || '[]');
    } catch {
      history = [];
    }
    history = appendWorkflowHistoryEntry(history, { state: targetStatus.template_id, user_id: user.id, timestamp: new Date().toISOString(), event: 'event_bypass', ...(normalizedComment ? { comment: normalizedComment } : {}) });
    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'currentState', value: [targetStatus.template_id] },
      { key: 'history', value: [JSON.stringify(history)] },
      { key: 'pendingStatus', value: [null] },
      { key: 'pendingError', value: [null] },
      { key: 'pendingTransition', value: [null] },
    ]);
    const projected = await projectWorkflowState(executionContext, executionUser, entity, targetStatus.template_id, scope, pendingTransition.closingReason);
    if (!projected && isClosingReasonLost(pendingTransition.closingReason, entity)) {
      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingError', value: [closingReasonNotWrittenError(pendingTransition.closingReason ?? null)] },
      ]);
    }
    if (requestAccessOutcome) {
      await recordRequestAccessDecision(executionContext, executionUser, entity as BasicStoreEntityCaseRfi, requestAccessOutcome, instanceId);
    } else if (requestAccessStatus) {
      await mirrorRequestAccessStatus(executionContext, executionUser, entity.internal_id || entity.id, requestAccessStatus);
    }
    return { success: true, newState: targetStatus.template_id, executionStatus: 'completed', entity };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'pendingStatus', value: ['error'] },
      { key: 'pendingError', value: [reason] },
      { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
    ]);
    return { success: false, executionStatus: 'error', reason, entity };
  }
};

export const setWorkflowStatus = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  targetStatusId: string,
  applyTransitionActions: boolean,
  comment?: string | null,
  runtimeParams: Record<string, unknown> = {},
): Promise<TriggerResult> => {
  if (!isBypassUser(user)) throw FunctionalError('BYPASS permission is required');
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) throw FunctionalError('Entity not found', { entityId });
  const lock = await lockResources([`workflow-mutation-${entity.internal_id || entity.id}`]);
  let result: TriggerResult;
  try {
    result = await executeWorkflowBypass(context, user, entityId, targetStatusId, applyTransitionActions, comment, runtimeParams);
  } finally {
    await lock.unlock();
  }
  if (result.success && result.executionStatus === 'completed' && !result.unchanged && comment?.trim()) {
    await notifyWorkflowTransitionComment(bypassDraftContext(context), result.entity, 'event_bypass', comment.trim(), user.id);
  }
  return result.success ? { ...result, instance: await getWorkflowInstance(context, user, entityId) } : result;
};

/**
 * Initialize the workflow instance for a newly created entity and fire the
 * onEnter hooks of the initial state. No-op if no workflow is configured for
 * the entity type or if an instance already exists.
 */
export const initializeEntityWorkflow = async (
  context: AuthContext,
  user: AuthUser,
  entity: any,
): Promise<void> => {
  // Avoid self-referential/unnecessary work for the internal objects created by workflow
  // initialization itself: the `has-workflow` relationship and the WorkflowInstance entity.
  if (entity.entity_type === RELATION_HAS_WORKFLOW || entity.entity_type === ENTITY_TYPE_WORKFLOW_INSTANCE) return;
  // Never eagerly initialize a workflow for an entity created/updated inside a draft
  if (getDraftContext(context, user)) return;
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const entitySetting = await getWorkflowConfig(executionContext, executionUser, entity.entity_type);
  const resolved = await resolveEntityDefinition(executionContext, executionUser, entity, entitySetting);
  if (!resolved.definitionData) return;
  await ensureWorkflowInstance(executionContext, executionUser, entity, resolved.definitionData, resolved);
};

const parseWorkflowHistory = (instanceEntity: WorkflowInstanceStoreEntity): any[] => {
  try {
    return JSON.parse(instanceEntity.history || '[]');
  } catch {
    return [];
  }
};

const parsePendingTransition = (instanceEntity: WorkflowInstanceStoreEntity): WorkflowPendingTransition | null => {
  try {
    return instanceEntity.pendingTransition ? JSON.parse(instanceEntity.pendingTransition) : null;
  } catch {
    return null;
  }
};

/**
 * Refuses to decide a request access while the background share of its requested entities has failed: part of
 * the access may already be granted, so the request cannot be declined, nor approved some other way, until the
 * failed transition is fired again or an admin clears it.
 */
const assertNoFailedRequestAccessShare = (instanceEntity: WorkflowInstanceStoreEntity, eventName: string, toState: string | null | undefined): void => {
  if (instanceEntity.pendingStatus !== 'error') return;
  const failedTransition = parsePendingTransition(instanceEntity);
  const shareFailed = (failedTransition?.asyncActions ?? []).some((slot) => slot.type === 'shareRequestedEntities' && slot.status === 'failed');
  const isRetry = failedTransition?.event === eventName && failedTransition?.toState === toState;
  if (shareFailed && !isRetry) {
    throw FunctionalError('The background share of the requested entities failed: retry it before deciding the request', { event: eventName });
  }
};

// An external write the workflow keeps on the entity without moving to it. Read-repair skips its
// Status while it is the latest meaningful history entry: a later transition, sync or admin clear ends it.
const EVENT_EXTERNAL_KEPT = 'event_external_kept';
const EVENT_EXTERNAL_IGNORED = 'event_external_ignored';
const EVENT_ADMIN_CLEAR = 'admin_clear_pending_state';

const findKeptExternalStatusId = (instanceEntity: WorkflowInstanceStoreEntity): string | undefined => {
  const entry = parseWorkflowHistory(instanceEntity).findLast((e) => e.event !== EVENT_EXTERNAL_IGNORED);
  return entry?.event === EVENT_EXTERNAL_KEPT ? entry.status_id : undefined;
};

const recordKeptExternalWrite = async (
  context: AuthContext,
  user: AuthUser,
  instanceEntity: WorkflowInstanceStoreEntity,
  newStatusId: string,
  reason: 'unmapped' | 'no_transition' | 'transition_has_actions' | 'sync_failed',
  message: string,
): Promise<void> => {
  const history = appendWorkflowHistoryEntry(parseWorkflowHistory(instanceEntity), {
    state: instanceEntity.currentState,
    status_id: newStatusId,
    reason,
    user_id: user.id,
    timestamp: now(),
    event: EVENT_EXTERNAL_KEPT,
  });
  const inputs: EditInput[] = [{ key: 'history', value: [JSON.stringify(history)] }];
  // A pending or failed transition keeps its own error.
  if (!instanceEntity.pendingStatus) {
    inputs.push({ key: 'pendingError', value: [message] });
  }
  await updateAttribute(context, WORKFLOW_MANAGER_USER, instanceEntity.internal_id || instanceEntity.id, ENTITY_TYPE_WORKFLOW_INSTANCE, inputs);
};

const applyExternalStatusWrite = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity,
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  instanceEntity: WorkflowInstanceStoreEntity,
  definitionData: WorkflowDefinitionResponse,
  newStatusId: string,
): Promise<void> => {
  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  const updateInstance = (inputs: EditInput[]) => updateAttribute(context, WORKFLOW_MANAGER_USER, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, inputs);
  // A pending transition wins: its completion projects its own state.
  if (instanceEntity.pendingStatus === 'pending') {
    const history = appendWorkflowHistoryEntry(parseWorkflowHistory(instanceEntity), {
      state: instanceEntity.currentState,
      status_id: newStatusId,
      user_id: user.id,
      timestamp: now(),
      event: EVENT_EXTERNAL_IGNORED,
    });
    await updateInstance([{ key: 'history', value: [JSON.stringify(history)] }]);
    return;
  }
  const stateId = await resolveEntityStatusState(context, definitionData, instanceEntity.scope, newStatusId);
  if (!stateId) {
    await recordKeptExternalWrite(context, user, instanceEntity, newStatusId, 'unmapped', `x_opencti_workflow_id was set to Status "${newStatusId}", which does not map to any state of the published workflow`);
    return;
  }
  if (stateId === instanceEntity.currentState) {
    if (instanceEntity.pendingError && !instanceEntity.pendingStatus) {
      await updateInstance([{ key: 'pendingError', value: [null] }]);
    }
    return;
  }
  // Actions never run on this path, so only BYPASS, or an allowed transition with nothing to run
  // or ask (no action, no required comment or closing reason, no onExit/onEnter), may move the state.
  if (!isBypassUser(user)) {
    const transition = (await getAllowedTransitions(context, user, entity.internal_id, {
      entity, entitySetting, definitionData, instanceEntity, statuses: [],
    })).find((allowed) => allowed.toState === stateId);
    if (!transition) {
      await recordKeptExternalWrite(context, user, instanceEntity, newStatusId, 'no_transition', `x_opencti_workflow_id was set to Status "${newStatusId}", but no transition allowed for this user leads from "${instanceEntity.currentState}" to "${stateId}"`);
      return;
    }
    const states = definitionData.states ?? [];
    const hasStateActions = (states.find((state) => state.statusId === instanceEntity.currentState)?.onExit ?? []).length > 0
      || (states.find((state) => state.statusId === stateId)?.onEnter ?? []).length > 0;
    if (transition.actions.length > 0 || transition.comment === 'required' || transition.closingReason === 'required' || hasStateActions) {
      await recordKeptExternalWrite(context, user, instanceEntity, newStatusId, 'transition_has_actions', `x_opencti_workflow_id was set to Status "${newStatusId}", but the transition to "${stateId}" has actions or requires a comment or a closing reason: trigger it from the workflow instead`);
      return;
    }
  }
  const failedTransition = instanceEntity.pendingStatus === 'error';
  const history = appendWorkflowHistoryEntry(parseWorkflowHistory(instanceEntity), {
    state: stateId,
    status_id: newStatusId,
    user_id: user.id,
    timestamp: now(),
    event: 'event_external',
    ...(failedTransition ? { cleared_failed_transition: parsePendingTransition(instanceEntity)?.event ?? null } : {}),
  });
  await updateInstance([
    { key: 'currentState', value: [stateId] },
    { key: 'history', value: [JSON.stringify(history)] },
    ...(failedTransition ? [{ key: 'pendingStatus', value: [null] }, { key: 'pendingTransition', value: [null] }] : []),
    { key: 'pendingError', value: [null] },
  ]);
  if (clearsClosingReason(entity.entity_type, definitionData.transitions, instanceEntity.currentState, stateId)) {
    const projected = await projectWorkflowState(context, WORKFLOW_MANAGER_USER, entity, stateId, resolveProjectionScope(instanceEntity.scope), null);
    if (!projected && isClosingReasonLost(null, entity)) {
      await updateInstance([{ key: 'pendingError', value: [closingReasonNotWrittenError(null)] }]);
    }
  }
};

// Best effort, without the lock: keeps read-repair from silently reverting a write the sync could not apply.
// A concurrent history write by a lock holder can still drop this entry.
const recordFailedExternalSync = async (context: AuthContext, user: AuthUser, entityId: string, newStatusId: string): Promise<void> => {
  try {
    const executionContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };
    // A later write replaced the status: its own sync owns the instance.
    const storedEntity = await storeLoadById<BasicStoreEntity>(executionContext, WORKFLOW_MANAGER_USER, entityId, 'Basic-Object');
    if (storedEntity?.x_opencti_workflow_id !== newStatusId) return;
    const instanceEntity = await findWorkflowInstanceEntity(executionContext, WORKFLOW_MANAGER_USER, entityId);
    if (instanceEntity) {
      await recordKeptExternalWrite(executionContext, user, instanceEntity, newStatusId, 'sync_failed', `x_opencti_workflow_id was set to Status "${newStatusId}", but the workflow could not be synced`);
    }
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Failed to record failed WorkflowInstance sync', { cause: error, entityId, newStatusId });
  }
};

/**
 * Keep the WorkflowInstance aligned when x_opencti_workflow_id is written outside the workflow
 * engine. The write itself is never rejected. The state moves only for a writer with BYPASS, or
 * through an allowed transition with no action and no required comment; any other write is kept on
 * the entity, recorded in history, and sets a pendingError. Never throws, the write is already saved.
 */
export const syncWorkflowInstanceFromExternalWrite = async (
  context: AuthContext,
  user: AuthUser,
  entity: any,
  newStatusId: string | null | undefined,
): Promise<void> => {
  // A cleared status cannot be a workflow state: read-repair projects the current one back.
  if (!newStatusId || getDraftContext(context, user)) return;
  const entityId = entity.internal_id || entity.id;
  try {
    const executionContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };
    const entitySetting = await getWorkflowConfig(executionContext, WORKFLOW_MANAGER_USER, entity.entity_type);
    if (!hasWorkflowDefinition(entitySetting)) return;
    const lock = await lockResources([`workflow-mutation-${entityId}`]);
    try {
      // A later write may have replaced the status while waiting for the lock: its own sync wins.
      const storedEntity = await storeLoadById<BasicStoreEntity>(executionContext, WORKFLOW_MANAGER_USER, entityId, entity.entity_type);
      if (storedEntity?.x_opencti_workflow_id !== newStatusId) return;
      // No instance yet: the next getWorkflowInstance read backfills it.
      const { instanceEntity, definitionData } = await resolveEntityDefinition(executionContext, WORKFLOW_MANAGER_USER, storedEntity, entitySetting);
      if (instanceEntity && definitionData) {
        await applyExternalStatusWrite(executionContext, user, storedEntity, entitySetting, instanceEntity, definitionData, newStatusId);
      }
    } finally {
      await lock.unlock();
    }
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Failed to sync WorkflowInstance from external status write', { cause: error, entityId, newStatusId });
    await recordFailedExternalSync(context, user, entityId, newStatusId);
  }
};

/**
 * Refuses a write of x_opencti_workflow_id made outside the workflow engine that moves a request into or
 * out of its Approved / Declined state: only a transition or a bypass decides a request. Also refuses one
 * that puts an RFI carrying a request record on the request access workflow: only the request access form
 * starts a request. Any other external write is left to the tolerant sync. Runs before the write is saved.
 */
export const assertExternalStatusWriteAllowed = async (
  context: AuthContext,
  _user: AuthUser,
  entity: { entity_type: string; internal_id?: string; x_opencti_workflow_id?: string },
  newStatusId: string | null,
): Promise<void> => {
  if (entity.entity_type !== ENTITY_TYPE_CONTAINER_CASE_RFI || newStatusId === (entity.x_opencti_workflow_id ?? null)) return;
  const workflowState = await resolveRequestAccessWorkflowState(context, entity as BasicStoreEntity);
  if (!workflowState) {
    // A plain or Global RFI is no request: it never lands on Approved / Declined, which would show it decided
    if (await isRequestAccessOutcomeStatus(context, entity.entity_type, newStatusId)) {
      throw FunctionalError('Approved and Declined can only be reached or left through the workflow', { id: entity.internal_id });
    }
    // Nor does the write make it one: its record would then decide what an approval shares and with whom
    const entityAfterWrite = { ...entity, x_opencti_workflow_id: newStatusId ?? undefined } as BasicStoreEntity;
    if (await resolveRequestAccessWorkflowState(context, entityAfterWrite)) {
      throw FunctionalError('A request access can only be created through the request access form', { id: entity.internal_id });
    }
    return;
  }
  const { definitionData, currentState } = workflowState;
  // A status of another type or scope maps to no state of the request access workflow
  const newStatus = await findStatusInCache(context, newStatusId);
  const newState = newStatus?.type === ENTITY_TYPE_CONTAINER_CASE_RFI && newStatus.scope === StatusScope.RequestAccess ? newStatus.template_id : null;
  if (newState === currentState) return;
  if (findStateOutcome(definitionData, currentState) || findStateOutcome(definitionData, newState)) {
    throw FunctionalError('Approved and Declined can only be reached or left through the workflow', { id: entity.internal_id });
  }
};

/**
 * Refuses a write of x_opencti_request_access made outside the workflow engine on a Case-Rfi whose request is,
 * or would become, decided on the request access workflow: the request record is owned by the workflow, which
 * alone decides it with its share, audit, count and notification. The state after the write is checked too,
 * so a record cannot be added to a plain RFI on a request access status. Requests on the legacy flow keep
 * their legacy writes. Runs before the write is saved.
 */
export const assertExternalRequestAccessWriteAllowed = async (
  context: AuthContext,
  entity: BasicStoreEntity,
  newRequestAccessValues: (string | null)[],
  newStatusId: string | null | undefined,
): Promise<void> => {
  if (entity.entity_type !== ENTITY_TYPE_CONTAINER_CASE_RFI) return;
  const { x_opencti_request_access: currentRequestAccess } = entity as { x_opencti_request_access?: string };
  if (newRequestAccessValues.every((value) => value === (currentRequestAccess ?? null))) return;
  // A malformed record reads as no request, which would hand its RFI back to the direct status edit
  if (newRequestAccessValues.some((value) => value !== null && !isRequestAccessRecord(value))) {
    throw FunctionalError(`Request access must be a JSON object of at most ${REQUEST_ACCESS_MAX_LENGTH} characters`, { id: entity.internal_id });
  }
  const entityAfterWrite = {
    ...entity,
    x_opencti_request_access: newRequestAccessValues.at(-1) ?? undefined,
    ...(newStatusId !== undefined ? { x_opencti_workflow_id: newStatusId ?? undefined } : {}),
  } as BasicStoreEntity;
  if (await resolveRequestAccessWorkflowState(context, entity) || await resolveRequestAccessWorkflowState(context, entityAfterWrite)) {
    throw FunctionalError('Request access can only be changed through the workflow', { id: entity.internal_id });
  }
};

/**
 * True when `statusId` is the Approved / Declined status of the request access workflow of a Case-Rfi:
 * a state only a transition or a bypass may reach.
 */
export const isRequestAccessOutcomeStatus = async (
  context: AuthContext,
  entityType: string,
  statusId: string | null | undefined,
): Promise<boolean> => {
  if (entityType !== ENTITY_TYPE_CONTAINER_CASE_RFI || !statusId) return false;
  const status = await findStatusInCache(context, statusId);
  if (status?.type !== ENTITY_TYPE_CONTAINER_CASE_RFI || status.scope !== StatusScope.RequestAccess) return false;
  const entitySetting = await getWorkflowConfig(context, SYSTEM_USER, entityType);
  const definitionData = await getDefinitionData(context, SYSTEM_USER, entitySetting, false, StatusScope.RequestAccess);
  return !!definitionData && !!findStateOutcome(definitionData, status.template_id);
};

/**
 * Refuses the creation of a Case-Rfi that supplies the Approved / Declined status of the request access
 * workflow: the request would exist already decided, with no transition, share or notification. A creation
 * starts a request at the initial state; only a transition or a bypass decides it. Runs before the entity is saved.
 */
export const assertExternalStatusCreateAllowed = async (
  context: AuthContext,
  entityType: string,
  statusId: string | null | undefined,
): Promise<void> => {
  if (await isRequestAccessOutcomeStatus(context, entityType, statusId)) {
    throw FunctionalError('Approved and Declined can only be reached or left through the workflow', { statusId });
  }
};

/**
 * Refuses the creation of a Case-Rfi carrying a request record by anyone but the request access form, which
 * creates it as the system, while the request access workflow is published: the record decides what an approval
 * shares and with whom, so a caller must not supply one of its own. Whatever the supplied status: an RFI created
 * on none or a Global one can still be moved onto the request access workflow afterwards. Runs before the entity
 * is saved.
 */
export const assertExternalRequestAccessCreateAllowed = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  requestAccess: string | null | undefined,
): Promise<void> => {
  if (entityType !== ENTITY_TYPE_CONTAINER_CASE_RFI || !requestAccess) return;
  // A malformed record reads as no request, which would hand the RFI to the direct status edit
  if (!isRequestAccessRecord(requestAccess)) {
    throw FunctionalError(`Request access must be a JSON object of at most ${REQUEST_ACCESS_MAX_LENGTH} characters`);
  }
  if (isInternalUser(user) || !isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) return;
  const entitySetting = await getWorkflowConfig(context, SYSTEM_USER, entityType);
  const definitionData = await getDefinitionData(context, SYSTEM_USER, entitySetting, false, StatusScope.RequestAccess);
  if (definitionData) {
    throw FunctionalError('A request access can only be created through the request access form');
  }
};

/**
 * Delete the WorkflowInstance (if any) associated to an entity that is being deleted.
 * The `has-workflow` relationship pointing to it is already cleaned up generically by
 * elDeleteElements' relation cascade, but the WorkflowInstance document itself is a
 * separate entity and would otherwise be left orphaned. No-op if no instance exists.
 */
export const cleanupEntityWorkflow = async (
  context: AuthContext,
  user: AuthUser,
  entity: any,
): Promise<void> => {
  if (entity.entity_type === ENTITY_TYPE_WORKFLOW_INSTANCE) return;
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
  if (!instanceEntity) return;
  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  await deleteElementById(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE);
};

/**
 * True if any of the given workflow versions (published/draft) uses `statusTemplateId` as a
 * canonical state (`initialState`, a transition endpoint, or `states[].statusId`). Shared by
 * `isStatusTemplateUsedInWorkflows` (platform-wide) and `isStatusUsedInWorkflow` (single workflow).
 *
 * Uses `extractCanonicalStateIds` instead of only `states[].statusId`, since a state can be
 * used solely via `initialState`/a transition endpoint without a `states` entry.
 */
const doAnyVersionsReferenceStatusTemplate = (
  versions: Array<WorkflowVersion | null | undefined>,
  statusTemplateId: string,
): boolean => {
  const definedVersions = versions.filter((v): v is WorkflowVersion => v !== undefined && v !== null);
  for (const version of definedVersions) {
    const content = version.content;
    let parsed;
    try {
      parsed = typeof content === 'string' ? JSON.parse(content) : content;
    } catch (_error) {
      // Malformed content is not this function's concern; skip rather than false-positive.
      continue;
    }
    const definitionData = {
      initialState: parsed?.initialState,
      states: parsed?.states ?? [],
      transitions: parsed?.transitions ?? [],
    };
    const canonicalStateIds = extractCanonicalStateIds(definitionData as Parameters<typeof extractCanonicalStateIds>[0]);
    if (canonicalStateIds.has(statusTemplateId)) {
      return true;
    }
  }
  return false;
};

/**
 * True if `statusTemplateId` is mapped by a state in any workflow (published or draft) on the
 * platform, regardless of entity type or scope. Appropriate when deleting the shared
 * `StatusTemplate` itself, since any workflow referencing it would break. NOT appropriate for
 * guarding the deletion of a single `Status`, which is specific to one entity type and scope —
 * use `isStatusUsedInWorkflow` for that.
 */
export const isStatusTemplateUsedInWorkflows = async (
  context: AuthContext,
  user: AuthUser,
  statusTemplateId: string,
): Promise<boolean> => {
  const executionContext = bypassDraftContext(context);
  const workflows = await fullEntitiesList<WorkflowDefinitionEntity>(
    executionContext,
    bypassDraftUser(user),
    [ENTITY_TYPE_WORKFLOW_DEFINITION],
  );
  return workflows.some((workflow) => doAnyVersionsReferenceStatusTemplate(
    [workflow.published_version, workflow.draft_version],
    statusTemplateId,
  ));
};

/**
 * True if this specific `Status` is referenced by the workflow mapping applicable to its own
 * entity type and scope. A `Status` is specific to a `StatusTemplate`, an entity type, and a
 * scope, so only the workflow actually wired to that entity type/scope can legitimately block
 * its deletion — unlike `isStatusTemplateUsedInWorkflows`, which checks every workflow on the
 * platform and would false-positive on unrelated entity types sharing the same template.
 */
export const isStatusUsedInWorkflow = async (
  context: AuthContext,
  user: AuthUser,
  status: BasicWorkflowStatus,
): Promise<boolean> => {
  const scope = status.scope === StatusScope.RequestAccess ? StatusScope.RequestAccess : StatusScope.Global;
  // The legacy request access settings still name their Approved / Declined statuses.
  if (scope === StatusScope.RequestAccess && await isStatusReferencedByRequestAccessWorkflow(context, user, status.id)) {
    return true;
  }

  const entitySetting = await getWorkflowConfig(context, user, status.type);
  const definitionId = resolveScopedDefinitionId(entitySetting, scope);
  if (!definitionId) {
    return false;
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    definitionId,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    return false;
  }

  return doAnyVersionsReferenceStatusTemplate(
    [workflowDefinitionEntity.published_version, workflowDefinitionEntity.draft_version],
    status.template_id,
  );
};

/**
 * Admin escape hatch: force-clear the pending state of a workflow instance.
 * Leaves currentState unchanged. Logs the intervention in history for audit.
 * Any still-running background tasks become orphaned (admin's conscious decision).
 */
export const clearWorkflowPendingState = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<any> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) throw FunctionalError('Entity not found', { entityId });

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const effectiveEntityId = entity.internal_id || entity.id;
  const lock = await lockResources([`workflow-mutation-${effectiveEntityId}`]);
  try {
    const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
    if (!instanceEntity) throw FunctionalError('No workflow instance found for entity', { entityId });

    let historyArr: any[];
    try {
      historyArr = JSON.parse(instanceEntity.history || '[]');
    } catch {
      historyArr = [];
    }
    historyArr = appendWorkflowHistoryEntry(historyArr, {
      state: instanceEntity.currentState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: EVENT_ADMIN_CLEAR,
      note: 'Admin force-cleared pending workflow transition state',
    });

    const instanceId = instanceEntity.internal_id || instanceEntity.id;
    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'pendingStatus', value: [null] },
      { key: 'pendingError', value: [null] },
      { key: 'pendingTransition', value: [null] },
      { key: 'history', value: [JSON.stringify(historyArr)] },
    ]);
  } finally {
    await lock.unlock();
  }

  return getWorkflowInstance(context, user, entityId);
};
