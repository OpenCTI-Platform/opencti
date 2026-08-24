import { randomUUID } from 'node:crypto';
import { booleanConf, logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { registerPostAttributeUpdateHook, registerPostEntityCreationHook } from '../../../database/entity-lifecycle-hooks';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { loadAssignees, loadParticipants } from '../../../database/members';
import { createEntity, createRelation, loadEntity, updateAttribute } from '../../../database/middleware';
import { fullEntitiesList, internalLoadById, storeLoadById } from '../../../database/middleware-loader';
import { READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY } from '../../../database/utils';
import { createListTask } from '../../../domain/backgroundTask-common';
import { createStatus } from '../../../domain/status';
import { resolveUserById } from '../../../domain/user';
import { checkEnterpriseEdition } from '../../../enterprise-edition/ee';
import { type EditInput, FilterMode, FilterOperator, StatusScope } from '../../../generated/graphql';
import { addWorkflowPublishCount } from '../../../manager/telemetryManager';
import { ENTITY_TYPE_STATUS, ENTITY_TYPE_STATUS_TEMPLATE } from '../../../schema/internalObject';
import { RELATION_HAS_WORKFLOW } from '../../../schema/internalRelationship';
import type { BasicStoreEntity, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { SYSTEM_USER, WORKFLOW_MANAGER_USER } from '../../../utils/access';
import { bypassDraftContext } from '../../../utils/draftContext';
import { now } from '../../../utils/format';
import { DRAFT_OPERATION_UPDATE_LINKED } from '../../draftWorkspace/draftOperations';
import { findByType as findEntitySettingByType } from '../../entitySetting/entitySetting-domain';
import type { BasicStoreEntityEntitySetting } from '../../entitySetting/entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../entitySetting/entitySetting-types';
import { addNotification } from '../../notification/notification-domain';
import type { NotificationAddInput } from '../../notification/notification-types';
import { WorkflowFactory } from '../engine/workflow-factory';
import type { WorkflowSchema } from '../engine/workflow-schema';
import { type ConvertStatusToDefinitionResult, convertStatusToDefinition } from '../migration/status-to-definition-converter';
import {
    type AsyncActionSlot,
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
import { extractAllStatesFromDefinition, validateWorkflowDefinitionData } from '../workflow-validation';
import { computeStateOrder, isEndingState } from './workflow-ordering';
import { projectWorkflowState, resolveMappedStatusId, resolveProjectionScope } from './workflow-projection';

// EE-only action types – conditions on transitions and onEnter/onExit state actions.
// 'validateDraft' is a CE feature and must NOT be listed here.
const EE_ONLY_ACTION_TYPES = new Set<WorkflowActionConfig['type']>(['updateAuthorizedMembers', 'shareWithOrganizations', 'unshareFromOrganizations', 'asyncBulkAction']);
const hasEEActions = (actions?: WorkflowActionConfig[]) => (actions ?? []).some((a) => EE_ONLY_ACTION_TYPES.has(a.type));
const hasConditions = (conditions?: WorkflowSerializedTransition['conditions']) => Array.isArray(conditions?.filters) && conditions.filters.length > 0;

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

interface WorkflowDefinitionResponse extends WorkflowSchema {
  published: boolean;
}

interface EntitySettingWithWorkflowResponse {
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
  history: string;
  pendingStatus?: string | null;
  pendingError?: string | null;
  pendingTransition?: string | null;
  entity_id: string;
  /**
   * Scope tag for this instance — `'standard'` by default, or the `StatusScope` value of the
   * `Status` the instance was initialized from when the entity was created with an explicit,
   * resolvable `x_opencti_workflow_id` (e.g. `'REQUEST_ACCESS'`). Missing on rows created before
   * this field existed (all pre-existing `DraftWorkspace` instances) — treat as `'standard'`.
   */
  scope?: string;
}

const getWorkflowConfig = async (
  context: AuthContext,
  user: AuthUser,
  targetType: string,
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  const executionContext = bypassDraftContext(context);
  return findEntitySettingByType(executionContext, executionContext.user!, targetType);
};

/**
 * Get workflow definition data based on allowDraft parameter.
 *
 * Task 7, Step 1.3/2.1-2.2: `scope` selects which WorkflowDefinition id to resolve from the
 * EntitySetting — `StatusScope.RequestAccess` prefers the dedicated
 * `request_access_workflow.workflow_definition_id` when configured, falling back to the standard
 * `workflow_id` otherwise (an entity type need not have a separate request_access
 * WorkflowDefinition to be usable within that scope). Defaults to `StatusScope.Global`,
 * preserving today's behavior for all existing callers.
 */
const getDefinitionData = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  allowDraft: boolean = false,
  scope: StatusScope = StatusScope.Global,
): Promise<WorkflowDefinitionResponse | null> => {
  if (!entitySetting) return null;

  const workflowDefinitionId = scope === StatusScope.RequestAccess
    ? (entitySetting.request_access_workflow?.workflow_definition_id ?? entitySetting.workflow_id)
    : entitySetting.workflow_id;

  if (workflowDefinitionId) {
    const executionContext = bypassDraftContext(context);
    const workflowDefinitionEntity = await storeLoadById(
      executionContext,
      executionContext.user!,
      workflowDefinitionId,
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
  return await loadEntity(executionContext, executionContext.user!, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['entity_id'], values: [entityId] }],
      filterGroups: [],
    },
  }) as WorkflowInstanceStoreEntity;
};

/**
 * Resolves a caller-supplied `x_opencti_workflow_id` (a `Status` id) to a workflow state at
 * entity-creation time, per Task 3 Step 2.5. Returns `null` if the status doesn't exist or
 * doesn't map to any state of the published definition — the caller must not treat this as an
 * error, only as "not resolvable" (case (b) of the three-case creation logic).
 */
const resolveSuppliedStatus = async (
  context: AuthContext,
  user: AuthUser,
  definitionData: WorkflowDefinitionResponse,
  suppliedStatusId: string,
): Promise<{ stateId: string; scope: string } | null> => {
  const status = await storeLoadById<BasicWorkflowStatus>(context, user, suppliedStatusId, ENTITY_TYPE_STATUS);
  if (!status) return null;
  const matchesState = (definitionData.states ?? []).some((s) => s.statusId === status.template_id);
  if (!matchesState) return null;
  return { stateId: status.template_id, scope: status.scope };
};

const initializeWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { id?: string; internal_id?: string; x_opencti_workflow_id?: string },
  entitySetting: BasicStoreEntityEntitySetting,
  definitionData: WorkflowDefinitionResponse,
): Promise<WorkflowInstanceStoreEntity> => {
  const entityId = entity.id || entity.internal_id;
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  // Resolve-then-project (Task 3, Step 2.4/2.5): three cases —
  // (a) explicit status resolves to a valid state: start there, no projection write.
  // (b) explicit status does not resolve: start at initialState with a pendingError
  //     diagnostic, no projection write — the caller-supplied field is never overwritten.
  // (c) no status supplied: start at initialState and project it onto the entity.
  let currentState = definitionData.initialState;
  let scope = 'standard';
  let pendingError: string | undefined;
  let shouldProject = false;

  const suppliedStatusId = entity.x_opencti_workflow_id;
  if (suppliedStatusId) {
    const resolved = await resolveSuppliedStatus(executionContext, executionUser, definitionData, suppliedStatusId);
    if (resolved) {
      currentState = resolved.stateId;
      scope = resolved.scope;
    } else {
      pendingError = `Supplied x_opencti_workflow_id "${suppliedStatusId}" does not resolve to any state of the published workflow`;
    }
  } else {
    shouldProject = true;
  }

  const instanceInput: Record<string, unknown> = {
    entity_id: entityId,
    // Task 7: the definition actually resolved (standard or request_access-scoped) — not
    // necessarily entitySetting.workflow_id, which only ever holds the standard definition's id.
    workflow_id: definitionData.id || 'manual',
    currentState,
    scope,
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
    // Only the Global scope is reconciled by Task 1's status mapping today; 'standard'
    // (this hook's default when no explicit status was supplied) maps onto it.
    await projectWorkflowState(executionContext, entity, currentState, StatusScope.Global);
  }

  return instance;
};

/**
 * Find the existing workflow instance for an entity, or create one and fire the
 * onEnter hooks of the initial state (sync only). Shared by triggerWorkflowEvent
 * and initializeEntityWorkflow so initialization is never duplicated.
 */
const ensureWorkflowInstance = async (
  executionContext: AuthContext,
  executionUser: AuthUser,
  entity: any,
  entitySetting: any,
  definitionData: any,
): Promise<WorkflowInstanceStoreEntity> => {
  const effectiveEntityId = entity.internal_id || entity.id;
  const existing = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
  if (existing) return existing;

  const instanceEntity = await initializeWorkflowInstance(
    executionContext,
    executionUser,
    entity as BasicStoreEntity & { id?: string; internal_id?: string },
    entitySetting,
    definitionData,
  );

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
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  return getDefinitionData(context, user, entitySetting, allowDraft, scope);
};

/**
 * Lightweight, non-admin-gated check for whether an entity type currently has a *published*
 * WorkflowDefinition (new engine). Used by the frontend's `StatusField` shared guard (Task 5,
 * Step 4.5) to decide whether the legacy free-choice Status dropdown must become read-only for
 * that type — deliberately exposed at a lower auth level than `workflowDefinition` (which is
 * `SETTINGS_SETCUSTOMIZATION`-gated and returns the full definition content), since knowledge
 * editors need this boolean on every entity edition form, not just settings admins.
 */
export const hasPublishedWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<boolean> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const definitionData = await getDefinitionData(context, user, entitySetting, false);
  return !!definitionData;
};

/**
 * Lightweight, non-admin-gated list of the published GLOBAL-scope WorkflowDefinition's distinct
 * transition event names for an entity type — used by the mass-edit "Apply transition" toolbar
 * option (Task 11), which must be usable by any KNOWLEDGE_KNUPDATE user, not just settings admins
 * (mirrors hasPublishedWorkflowDefinition's rationale for being exposed below workflowDefinition's
 * SETTINGS_SETCUSTOMIZATION gate).
 */
export const getWorkflowTransitionEvents = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<string[]> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const definitionData = await getDefinitionData(context, user, entitySetting, false);
  const events = (definitionData?.transitions ?? []).map((t) => t.event);
  return [...new Set(events)].sort();
};

/**
 * Task 6, Step 2.1: read-only preview of what migrating an entity type's legacy `Status` set to a
 * `WorkflowDefinition` would produce, one result per `StatusScope` present — no persisted changes.
 * Pure conversion logic lives in `convertStatusToDefinition`; this just gathers the `Status`/
 * `StatusTemplate` input data for `entityType` (all scopes, matching `byScope`'s shape).
 */
export const getWorkflowMigrationPreview = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<ConvertStatusToDefinitionResult> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const statuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['type'], values: [entityType] }],
      filterGroups: [],
    },
  });
  const templates = await fullEntitiesList<BasicWorkflowTemplateEntity>(executionContext, executionUser, [ENTITY_TYPE_STATUS_TEMPLATE]);
  return convertStatusToDefinition(statuses, templates);
};

/**
 * Returns the ID of the published version for the given entity setting's workflow, or null if not published.
 */
export const getWorkflowPublishedVersionId = async (
  context: AuthContext,
  entitySetting: BasicStoreEntityEntitySetting,
): Promise<string | null> => {
  if (!entitySetting.workflow_id) return null;
  const executionContext = bypassDraftContext(context);
  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionContext.user!,
    entitySetting.workflow_id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  return workflowDefinitionEntity?.published_version?.id ?? null;
};

/**
 * `scope` selects which of an entity type's two possible WorkflowDefinition ids (the standard
 * `workflow_id`, or the dedicated `request_access_workflow.workflow_definition_id`) a CRUD
 * operation reads/writes. Mirrors `getDefinitionData`'s own scope resolution (Task 7) but without
 * its Global-fallback, since authoring operations must know precisely whether a dedicated
 * RequestAccess definition already exists.
 */
const resolveScopedWorkflowDefinitionId = (
  entitySetting: BasicStoreEntityEntitySetting,
  scope: StatusScope,
): string | null | undefined => (
  scope === StatusScope.RequestAccess ? entitySetting.request_access_workflow?.workflow_definition_id : entitySetting.workflow_id
);

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
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  // Validate definition is valid JSON and respect schema
  let definitionObj;
  try {
    definitionObj = JSON.parse(definition);
  } catch (_error) {
    throw FunctionalError('Invalid workflow definition JSON');
  }

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

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const existingDefinitionId = resolveScopedWorkflowDefinitionId(entitySetting, scope);
  const errors = await validateWorkflowDefinitionData(executionContext, executionUser, definition, entityType, existingDefinitionId ?? undefined);

  const workflowName = definitionObj.name || `Workflow for ${entityType}`;

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

  // 3. Link it to the EntitySetting
  if (scope === StatusScope.RequestAccess) {
    const { element } = await updateAttribute(executionContext, executionUser, entitySetting.id, 'EntitySetting', [
      { key: 'request_access_workflow', value: [{ ...entitySetting.request_access_workflow, workflow_definition_id: workflowDefinition.id }] },
    ]);
    const raElementWithSetting = element as unknown as BasicStoreEntityEntitySetting;
    return {
      id: raElementWithSetting.id,
      workflow_id: workflowDefinition.id,
      target_type: raElementWithSetting.target_type,
      errors,
      published: false,
    } as EntitySettingWithWorkflowResponse;
  }

  const { element } = await updateAttribute(executionContext, executionUser, entitySetting.id, 'EntitySetting', [
    { key: 'workflow_id', value: [workflowDefinition.id] },
  ]);

  // New workflows have no published version yet
  const published = false;

  const elementWithSetting = element as unknown as BasicStoreEntityEntitySetting;
  return {
    id: elementWithSetting.id,
    workflow_id: elementWithSetting.workflow_id,
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
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  const existingDefinitionId = entitySetting ? resolveScopedWorkflowDefinitionId(entitySetting, scope) : undefined;
  if (entitySetting && existingDefinitionId) {
    const executionContext = bypassDraftContext(context);
    if (scope === StatusScope.RequestAccess) {
      const { element } = await updateAttribute(executionContext, executionContext.user!, entitySetting.id, 'EntitySetting', [
        { key: 'request_access_workflow', value: [{ ...entitySetting.request_access_workflow, workflow_definition_id: null }] },
      ]);
      return element as unknown as BasicStoreEntityEntitySetting;
    }
    const { element } = await updateAttribute(executionContext, executionContext.user!, entitySetting.id, 'EntitySetting', [
      { key: 'workflow_id', value: [null] },
    ]);
    return element as unknown as BasicStoreEntityEntitySetting;
  }
  return entitySetting;
};

/**
 * Ensures every workflow state's `statusId` (StatusTemplate reference) has a matching `Status`
 * record for this entity type in the Global scope, creating any that are missing. This is the
 * "full mapping invariant": after a successful publish, every declared state maps to a real
 * `Status` the legacy `status`/`x_opencti_workflow_id` field can point to.
 *
 * Only the Global scope is reconciled here — request-access-scoped `Status` routing (a separate
 * scope on the same entity type) is out of scope until Task 7 introduces per-scope workflow
 * definitions; existing `Status` records in other scopes are left untouched.
 */
export const ensureFullStatusMapping = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definitionData: WorkflowDefinitionData,
  scope: StatusScope = StatusScope.Global,
): Promise<void> => {
  const states = definitionData.states ?? [];
  if (states.length === 0) return;

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

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
  const existingTemplateIds = new Set(existingStatuses.map((status) => status.template_id));

  const computedOrder = computeStateOrder(definitionData.initialState, definitionData.transitions);

  for (const state of states) {
    if (!state.statusId || existingTemplateIds.has(state.statusId)) {
      continue;
    }
    const order = computedOrder.get(state.statusId) ?? state.order ?? 0;
    await createStatus(executionContext, executionUser, entityType, {
      template_id: state.statusId,
      order,
      scope,
    });
  }
};

// Grace period before an orphaned Status is eligible for hard deletion by the cleanup manager.
const STATUS_DELETION_GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * True if any entity of `entityType` currently has its legacy `x_opencti_workflow_id` field
 * pointing at this `Status`.
 */
const isStatusReferencedByEntity = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  statusId: string,
): Promise<boolean> => {
  const entities = await fullEntitiesList<any>(context, user, [entityType], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['x_opencti_workflow_id'], values: [statusId] }],
      filterGroups: [],
    },
  });
  return entities.length > 0;
};

/**
 * True if any EntitySetting's `request_access_workflow.{approved_workflow_id,declined_workflow_id}`
 * references this `Status` id, across ALL entity-setting configs (not just the one being
 * republished) — request-access routing is a separate reference path from workflow states.
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
 * On republish, reconciles `Status` records against the new definition's state→status mapping:
 * - A `Status` no longer mapped by any state, and unreferenced by any entity or request-access
 *   workflow config, is marked `to_be_deleted_at` (now + grace period) instead of being deleted
 *   immediately. The cleanup manager (a separate scheduled task) re-verifies and hard-deletes it
 *   once the grace period has elapsed.
 * - A `Status` still pending deletion that the new definition maps a state back to has its
 *   `to_be_deleted_at` mark cleared — restoring wins over a concurrent purge for the same record.
 */
const reconcileOrphanedStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  oldDefinitionData: WorkflowDefinitionData,
  newDefinitionData: WorkflowDefinitionData,
  scope: StatusScope = StatusScope.Global,
): Promise<void> => {
  const oldTemplateIds = new Set((oldDefinitionData.states ?? []).map((s) => s.statusId).filter((id): id is string => !!id));
  const newTemplateIds = new Set((newDefinitionData.states ?? []).map((s) => s.statusId).filter((id): id is string => !!id));

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
 * before the cleanup manager hard-deletes it. State can change during the grace window (a later
 * republish could remap a state back onto it, or an entity/request-access config could start
 * referencing it), so the same three checks used at mark-time are re-run here rather than trusting
 * the original mark. Used exclusively by the workflow status cleanup manager (Step 4.7).
 */
export const isStatusOrphaned = async (
  context: AuthContext,
  user: AuthUser,
  status: BasicWorkflowStatus,
): Promise<boolean> => {
  const definitionData = await getWorkflowDefinition(context, user, status.type, false, status.scope);
  const stillMapped = !!definitionData
    && (definitionData.states ?? []).some((s: { statusId?: string }) => s.statusId === status.template_id);
  if (stillMapped) return false;

  const referencedByEntity = await isStatusReferencedByEntity(context, user, status.type, status.id);
  if (referencedByEntity) return false;
  const referencedByRequestAccess = await isStatusReferencedByRequestAccessWorkflow(context, user, status.id);
  if (referencedByRequestAccess) return false;

  return true;
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
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  const existingDefinitionId = resolveScopedWorkflowDefinitionId(entitySetting, scope);
  if (!existingDefinitionId) {
    throw FunctionalError('No workflow definition to publish', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    existingDefinitionId,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: existingDefinitionId });
  }

  const draftVersion = workflowDefinitionEntity.draft_version;
  if (!draftVersion) {
    throw FunctionalError('No draft version to publish', { entityType });
  }

  // Check for validation errors
  if (draftVersion.validation_errors && draftVersion.validation_errors.length > 0) {
    throw FunctionalError('Cannot publish workflow with validation errors', {
      entityType,
      errorCount: draftVersion.validation_errors.length,
    });
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
      const oldStates = extractAllStatesFromDefinition(oldDef);
      const newStates = extractAllStatesFromDefinition(newDef);
      const removedStates = [...oldStates].filter((s) => !newStates.has(s));

      if (removedStates.length > 0) {
        // Ending states (no outgoing transitions) are safe to remove even with active instances.
        const statesWithOutgoingTransitions = new Set<string>();
        for (const transition of (oldDef.transitions ?? [])) {
          const fromStates = Array.isArray(transition.from) ? transition.from : [transition.from];
          for (const s of fromStates) {
            if (s && s !== '*') statesWithOutgoingTransitions.add(s);
          }
        }
        const nonEndingRemovedStates = removedStates.filter((s) => statesWithOutgoingTransitions.has(s));

        if (nonEndingRemovedStates.length > 0) {
          // Note: 'workflow_id' is a reserved special filter key (WORKFLOW_FILTER) in OpenCTI that maps to
          // entity workflow status (x_opencti_workflow_id). We cannot use it as a raw ES filter key.
          // Instead, we filter by currentState in ES and post-filter by workflow_id.
          const instancesInRemovedStates = await fullEntitiesList<any>(executionContext, executionUser, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
            filters: {
              mode: FilterMode.And,
              filters: [
                { key: ['currentState'], values: nonEndingRemovedStates, operator: FilterOperator.Eq, mode: FilterMode.Or },
              ],
              filterGroups: [],
            },
          });
          const conflictingInstances = instancesInRemovedStates.filter((inst: any) => inst.workflow_id === workflowDefinitionEntity.id);

          if (conflictingInstances.length > 0) {
            throw FunctionalError(
              'Cannot publish workflow: the following statuses are in use and cannot be removed. Move all items out of those statuses first.',
              { removedStates: nonEndingRemovedStates, entityType: ENTITY_TYPE_STATUS_TEMPLATE },
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
  }

  // CONSISTENCY GUARANTEE: published_version will be in all_versions (already there via draft)
  // Copy draft_version to published_version and clear the draft (no more unpublished changes).
  const updates: EditInput[] = [
    { key: 'published_version', value: [draftVersion] },
    { key: 'draft_version', value: [] },
  ];

  await updateAttribute(executionContext, executionUser, workflowDefinitionEntity.id, ENTITY_TYPE_WORKFLOW_DEFINITION, updates);

  if (workflowDefinitionEntity.published_version) {
    // Task 6, Step 3.4: this is a republish (not the entity type's very first-ever publish) —
    // reconcile any entity whose Status was written directly while mechanics were inactive
    // (e.g. during a rollback window), so the next read's repair doesn't silently discard it.
    await reconcileExternalWritesOnRepublish(executionContext, executionUser, entityType);
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

  const entitySettingWithWorkflow = entitySetting as BasicStoreEntityEntitySetting;
  return {
    id: entitySettingWithWorkflow.id,
    workflow_id: workflowDefinitionEntity.id,
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
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  const existingDefinitionId = resolveScopedWorkflowDefinitionId(entitySetting, scope);
  if (!existingDefinitionId) {
    throw FunctionalError('No workflow definition found', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    existingDefinitionId,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: existingDefinitionId });
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
    workflow_id: workflowDefinitionEntity.id,
    target_type: entitySettingWithWorkflow.target_type,
    errors: [],
    published: true,
  } as EntitySettingWithWorkflowResponse;
};

/**
 * Task 2, Step 4.6: per-process, per-entity rate limit for read-repair writes, so a page of
 * repeated reads for the same entity doesn't trigger a repair write on every single read.
 * Known limitation: this cache is per-process, so a multi-node deployment can still perform
 * one redundant repair per node within the TTL window — acceptable since repairs are
 * idempotent no-ops once consistent (see plan.md Task 2 Step 4.6).
 */
const READ_REPAIR_RATE_LIMIT_TTL_MS = 5000;
const readRepairLastAttemptByEntity = new Map<string, number>();

/** Test-only: clears the read-repair rate-limit cache so tests can exercise it from a clean state. */
export const __resetReadRepairRateLimitForTest = (): void => {
  readRepairLastAttemptByEntity.clear();
};

/**
 * Task 5, Step 0.7: per-request cap on read-repair writes. Read batching (`batchWorkflowInstances`)
 * only solves the read-burst case; a page of N entities that all diverge at once (e.g. right after
 * a type is migrated, before backfill) would otherwise still fire up to N concurrent repair writes
 * in a single GraphQL request. Keyed by the request's own `AuthContext` object identity (a fresh
 * context is created per request), so this never leaks across requests/nodes.
 */
const READ_REPAIR_WRITE_CAP_PER_REQUEST = 20;
let readRepairWriteCountByContext = new WeakMap<AuthContext, number>();

/** Test-only: resets the per-request repair-write cap so tests can exercise it from a clean state. */
export const __resetReadRepairWriteCapForTest = (): void => {
  readRepairWriteCountByContext = new WeakMap<AuthContext, number>();
};

/**
 * Pre-resolved per-entity data a batched caller (`batchWorkflowInstances`) has already fetched
 * in bulk, so a single `getWorkflowInstance`/`getAllowedTransitions` call doesn't redo the same
 * per-entity store round trips (entity fetch, entitySetting/definition resolution, WorkflowInstance
 * lookup) for every row of a batch (Task 5, Step 0.7).
 */
interface WorkflowInstancePrefetch {
  entity: any;
  entitySetting: BasicStoreEntityEntitySetting | undefined;
  definitionData: WorkflowDefinitionResponse | null;
  instanceEntity: WorkflowInstanceStoreEntity | null;
}

/**
 * Get workflow instance for an entity, with live pending transition data.
 */
export const getWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  prefetched?: WorkflowInstancePrefetch,
): Promise<any> => {
  const entity = prefetched ? prefetched.entity : await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return null;
  }

  const entitySetting = prefetched ? prefetched.entitySetting : await getWorkflowConfig(context, user, entity.entity_type);
  // Task 7: scope is a property of the entity's own currently-assigned status, not a hardcoded
  // default — a `RequestAccess`-scoped entity must resolve its dedicated definition, not Global's.
  const definitionData = prefetched
    ? prefetched.definitionData
    : await getDefinitionData(context, user, entitySetting, false, await resolveStatusScope(context, user, (entity as BasicStoreEntity).x_opencti_workflow_id));
  if (!definitionData) {
    return null;
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  let instanceEntity = prefetched ? prefetched.instanceEntity : await findWorkflowInstanceEntity(context, user, effectiveEntityId);
  if (!instanceEntity) {
    // Lazy backfill (Task 3, Step 3): a pre-existing entity created before this change has no
    // WorkflowInstance row yet. Create one now, under the system identity (never the reading
    // caller's), so future reads/reconciliation have a real instance to work with. A failed
    // backfill write must not fail this read — fall back to the pre-this-change synthesized
    // in-memory placeholder below.
    try {
      // `initializeWorkflowInstance`/`findWorkflowInstanceEntity` derive their execution
      // identity from `context.user` (via `bypassDraftContext`), not from a separately-passed
      // user argument — so the WORKFLOW_MANAGER_USER identity must be set on the context itself.
      const executionContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };
      instanceEntity = await ensureWorkflowInstance(executionContext, WORKFLOW_MANAGER_USER, entity, entitySetting!, definitionData);
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Failed to lazily backfill WorkflowInstance for entity, falling back to synthesized instance', { cause: error, entityId: effectiveEntityId });
    }
  }
  const currentState = instanceEntity?.currentState ?? definitionData.initialState;

  // Task 2, Step 4: read-repair — correct `x_opencti_workflow_id` divergence from `currentState`.
  // Never runs under the reading caller's identity, never fails/delays the read on error, and is
  // rate-limited per entity so repeated reads don't repeatedly re-write an already-consistent field.
  if (instanceEntity && currentState && !booleanConf('workflow:disable_read_repair', false)) {
    const lastAttempt = readRepairLastAttemptByEntity.get(effectiveEntityId);
    const withinRateLimit = lastAttempt !== undefined && (Date.now() - lastAttempt) < READ_REPAIR_RATE_LIMIT_TTL_MS;
    if (!withinRateLimit) {
      try {
        const scope = resolveProjectionScope(instanceEntity.scope);
        const expectedStatusId = await resolveMappedStatusId(context, entity.entity_type, scope, currentState);
        if (expectedStatusId && (entity as BasicStoreEntity).x_opencti_workflow_id !== expectedStatusId) {
          const requestWriteCount = readRepairWriteCountByContext.get(context) ?? 0;
          if (requestWriteCount >= READ_REPAIR_WRITE_CAP_PER_REQUEST) {
            logApp.warn('[OPENCTI-MODULE] Skipping read-repair write: per-request cap reached, entity remains unrepaired until a later request', { entityId: effectiveEntityId, cap: READ_REPAIR_WRITE_CAP_PER_REQUEST });
          } else {
            readRepairWriteCountByContext.set(context, requestWriteCount + 1);
            readRepairLastAttemptByEntity.set(effectiveEntityId, Date.now());
            const repairContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };
            await projectWorkflowState(repairContext, entity as BasicStoreEntity, currentState, scope);
            logApp.info('[OPENCTI-MODULE] Repaired x_opencti_workflow_id divergence from WorkflowInstance.currentState', { entityId: effectiveEntityId, entityType: entity.entity_type, currentState });
          }
        }
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Failed to read-repair x_opencti_workflow_id, returning unrepaired instance', { cause: error, entityId: effectiveEntityId });
      }
    }
  }

  const allowedTransitions = await getAllowedTransitions(
    context,
    user,
    entityId,
    { entity, entitySetting, definitionData, instanceEntity },
  );
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
    allowedTransitions,
    history: JSON.parse(instanceEntity?.history || '[]'),
    pendingStatus: instanceEntity?.pendingStatus ?? null,
    pendingError: instanceEntity?.pendingError ?? null,
    pendingTransition: pendingTransitionData,
    scope: instanceEntity?.scope ?? 'standard',
  };
};

/**
 * Bound on the bulk `WorkflowInstance` lookup issued by `batchWorkflowInstances` for a single
 * batch. Mirrors the same defensive bound used elsewhere for WorkflowInstance bulk reads
 * (`src/utils/filtering/workflow-status-filter.ts`) — a single GraphQL request embedding this
 * field on a paginated list is expected to stay well under this, but a real production list page
 * size would never realistically approach it either.
 */
const WORKFLOW_INSTANCE_BATCH_BOUND = 5000;

/**
 * Batched `getWorkflowInstance` for a page of entities (Task 5, Step 0.7). Resolving
 * `workflowInstance` as an embedded field on a list of N entities would otherwise issue N
 * sequential `WorkflowInstance` store lookups (plus N redundant entitySetting/definition
 * resolutions) — this collapses that into one bulk `WorkflowInstance` query (by `entity_id`)
 * and one config resolution per distinct entity type, then delegates the remaining per-entity
 * enrichment (pending-transition Work/BackgroundTask lookups, allowed-transition condition
 * evaluation) to `getWorkflowInstance` via its `prefetched` param so it skips redoing the lookups
 * already done here. Intended to be wired behind `batchLoader` (see `httpAuthenticatedContext.js`),
 * which is why results are returned in the same order as the input `entities` array.
 */
export const batchWorkflowInstances = async (
  context: AuthContext,
  user: AuthUser,
  entities: any[],
): Promise<any[]> => {
  // entitySetting only depends on entity type, so it's still resolved once per distinct type
  // regardless of how many distinct scopes are present among entities of that type.
  const entitySettingByType = new Map<string, BasicStoreEntityEntitySetting | undefined>();
  const distinctTypes = [...new Set(entities.map((e) => e.entity_type))];
  await Promise.all(distinctTypes.map(async (type) => {
    entitySettingByType.set(type, await getWorkflowConfig(context, user, type));
  }));

  // Task 7: scope is a property of each entity's own currently-assigned status — entities of the
  // same type but different scope (e.g. Global vs RequestAccess) may resolve to different
  // WorkflowDefinitions, so the definitionData cache below is keyed by `${entityType}:${scope}`.
  const scopeByEntity = new Map<any, StatusScope>();
  await Promise.all(entities.map(async (entity) => {
    scopeByEntity.set(entity, await resolveStatusScope(context, user, entity.x_opencti_workflow_id));
  }));

  const configByType = new Map<string, { entitySetting: BasicStoreEntityEntitySetting | undefined; definitionData: WorkflowDefinitionResponse | null }>();
  const distinctTypeScopeKeys = new Map<string, { type: string; scope: StatusScope }>();
  entities.forEach((entity) => {
    const scope = scopeByEntity.get(entity)!;
    distinctTypeScopeKeys.set(`${entity.entity_type}:${scope}`, { type: entity.entity_type, scope });
  });
  await Promise.all([...distinctTypeScopeKeys.entries()].map(async ([key, { type, scope }]) => {
    const entitySetting = entitySettingByType.get(type);
    const definitionData = await getDefinitionData(context, user, entitySetting, false, scope);
    configByType.set(key, { entitySetting, definitionData });
  }));

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const effectiveIds = entities.map((e) => e.internal_id || e.id);
  const bulkInstances = effectiveIds.length > 0
    ? await fullEntitiesList<WorkflowInstanceStoreEntity>(executionContext, executionUser, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
        first: WORKFLOW_INSTANCE_BATCH_BOUND,
        filters: {
          mode: FilterMode.And,
          filters: [{ key: ['entity_id'], values: effectiveIds, operator: FilterOperator.Eq, mode: FilterMode.Or }],
          filterGroups: [],
        },
      })
    : [];
  if (bulkInstances.length === WORKFLOW_INSTANCE_BATCH_BOUND) {
    logApp.warn('[OPENCTI-MODULE] batchWorkflowInstances hit its WorkflowInstance query bound, results may be incomplete', { requestedCount: entities.length, bound: WORKFLOW_INSTANCE_BATCH_BOUND });
  }
  const instanceByEntityId = new Map(bulkInstances.map((i) => [i.entity_id, i]));

  return Promise.all(entities.map((entity) => {
    const effectiveEntityId = entity.internal_id || entity.id;
    const config = configByType.get(`${entity.entity_type}:${scopeByEntity.get(entity)}`);
    return getWorkflowInstance(context, user, effectiveEntityId, {
      entity,
      entitySetting: config?.entitySetting,
      definitionData: config?.definitionData ?? null,
      instanceEntity: instanceByEntityId.get(effectiveEntityId) ?? null,
    });
  }));
};

/**
 * Get allowed transitions for an entity.
 */
export const getAllowedTransitions = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  prefetched?: WorkflowInstancePrefetch,
): Promise<Array<{ event: string; toState: string; comment?: string; isClosingTransition: boolean; actions: string[]; requiresShareOrganizationInput: boolean; requiresUnshareOrganizationInput: boolean }>> => {
  const entity = prefetched ? prefetched.entity : await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return [];
  }

  const entitySetting = prefetched ? prefetched.entitySetting : await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = prefetched
    ? prefetched.definitionData
    : await getDefinitionData(context, user, entitySetting, false, await resolveStatusScope(context, user, (entity as BasicStoreEntity).x_opencti_workflow_id));

  if (!definitionData) {
    return [];
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = prefetched ? prefetched.instanceEntity : await findWorkflowInstanceEntity(context, user, effectiveEntityId);
  const currentStateId = instanceEntity?.currentState ?? definitionData.initialState;

  const definition = WorkflowFactory.createDefinition(definitionData);
  const effectiveStateId = currentStateId || definition.getInitialState();
  if (!effectiveStateId || !definition.hasState(effectiveStateId)) {
    return [];
  }

  const transitions = definition.getTransitions(effectiveStateId);

  // Pre-evaluate conditions against the requesting user so the frontend only
  // sees transitions the current user is actually allowed to trigger.
  const conditionContext = { entity, user, triggeringUser: user };
  const resolvedTransitions = (await Promise.all(
    transitions.map(async (transition) => {
      for (const condition of (transition.conditions ?? [])) {
        const passes = await condition(conditionContext as any);
        if (!passes) return null;
      }
      return {
        event: transition.event,
        toState: transition.to,
        comment: transition.comment,
        // Task 11: the target state has no outgoing transitions of its own (a terminal/"closing"
        // state) — the frontend uses this to offer closing-reason capture only for transitions
        // that actually close the entity, not every transition.
        isClosingTransition: isEndingState(definitionData.transitions ?? [], transition.to),
        actions: transition.actionTypes || [],
        requiresShareOrganizationInput: transition.requiresShareOrganizationInput ?? false,
        requiresUnshareOrganizationInput: transition.requiresUnshareOrganizationInput ?? false,
      };
    }),
  )).filter((t): t is NonNullable<typeof t> => t !== null);

  return resolvedTransitions;
};

/**
 * Task 8, Step 5: `WorkflowInstance.history` is rewritten wholesale on every append, so an
 * unbounded array means an ever-growing reindex cost on hot entities (e.g. routine connector
 * re-writes synced by `syncWorkflowInstanceFromExternalWrite`). Bounds it to the most recent
 * entries. Does not address the underlying per-write reindex cost of a monolithic array — a
 * high-frequency writer may still need an append-only substore instead of this single array.
 */
const MAX_WORKFLOW_HISTORY_ENTRIES = 200;
const appendWorkflowHistoryEntry = (history: any[], entry: any): any[] => {
  return [...history, entry].slice(-MAX_WORKFLOW_HISTORY_ENTRIES);
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
 * @param closingReason Task 11: optional dedicated reason captured when the transition lands on a
 *   closing (ending) state — stored separately from `comment` in the workflow history entry.
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
): Promise<TriggerResult> => {
  // 1. Fetch the entity
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    throw FunctionalError('Entity not found', { entityId });
  }

  // 2. Fetch its EntitySetting to get the workflow configuration
  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  // Task 7: resolve scope from the entity's own currently-assigned status, not a hardcoded Global default.
  const scope = await resolveStatusScope(context, user, (entity as BasicStoreEntity).x_opencti_workflow_id);
  const definitionData = await getDefinitionData(context, user, entitySetting, false, scope);

  if (!definitionData) {
    return {
      success: false,
      reason: `Workflows are not configured for entity type: ${entity.entity_type}`,
    };
  }

  try {
    const executionContext = bypassDraftContext(context);
    const executionUser = executionContext.user!;

    const instanceEntity = await ensureWorkflowInstance(executionContext, executionUser, entity, entitySetting, definitionData);

    // 3. Lock check: reject new events while a transition is already pending
    if (instanceEntity.pendingStatus === 'pending') {
      return {
        success: false,
        reason: 'A workflow transition is already pending for this entity. Wait for it to complete, retry the failed action, or ask an admin to clear the pending state.',
      };
    }

    const currentStateId = instanceEntity.currentState;
    const definition = WorkflowFactory.createDefinition(definitionData);

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

    // 5. Create instance and trigger the event
    const instance = WorkflowFactory.getInstance(definitionData, definition, currentStateId || '', workflowContext);
    const result = await instance.trigger(eventName);

    if (!result.success) {
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

      // Get the serialized transition to persist its syncActions for phase-2 execution.
      const targetTransitionForSync = definitionData.transitions?.find((t: any) => {
        const fromStates = Array.isArray(t.from) ? t.from : [t.from];
        return fromStates.includes(currentStateId) && t.event === eventName;
      });
      // fallback on actions if syncActions not explicitly defined on transition (legacy support)
      const serializedTransitions: WorkflowActionConfig[] = targetTransitionForSync?.syncActions ?? [];

      // Collect the onEnter actions of the target state so phase 2 can replay them.
      const toStateId = targetTransitionForSync?.to ?? instance.getCurrentState();
      const targetStateDef = definitionData.states?.find((s: any) => s.statusId === toStateId);
      const serializedOnEnterActions: WorkflowActionConfig[] = targetStateDef?.onEnter ?? [];

      const pendingTransition: WorkflowPendingTransition = {
        event: eventName,
        toState: toStateId,
        triggeredBy: user.id,
        triggeredAt: new Date().toISOString(),
        runtimeParams,
        ...(comment ? { comment } : {}),
        ...(closingReason ? { closingReason } : {}),
        asyncActions: rawSlots,
        syncActions: serializedTransitions,
        ...(serializedOnEnterActions.length > 0 ? { onEnterActions: serializedOnEnterActions } : {}),
      };

      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['pending'] },
        { key: 'pendingError', value: [null] },
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
      ]);

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
      ...(comment ? { comment } : {}),
      ...(closingReason ? { closing_reason: closingReason } : {}),
    });

    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'currentState', value: [newState] },
      { key: 'history', value: [JSON.stringify(history)] },
    ]);

    // Task 2, Step 2.2: keep the legacy `x_opencti_workflow_id` in sync with the new state.
    // `projectWorkflowState` never throws (best-effort, logs and skips on failure).
    await projectWorkflowState(executionContext, entity as BasicStoreEntity, newState, resolveProjectionScope(instanceEntity.scope));

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
  }
};

/**
 * Task 9: bypass-update — sets an entity's `WorkflowInstance.currentState` directly to whatever
 * state the given `targetStatusId` maps to, without requiring an allowed-transition edge from the
 * current state (unlike `triggerWorkflowEvent`). Always records an `event_bypass` history entry
 * (never `event_external`, reserved for Task 8's non-workflow-engine writers). When
 * `applyTransitionActions` is true, runs only the current state's onExit and target state's
 * onEnter actions-on-status — never edge-level actions-on-transition, since bypass mode has no
 * edge to run them from.
 */
export const setWorkflowStatus = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  targetStatusId: string,
  applyTransitionActions: boolean,
  comment?: string,
  closingReason?: string,
): Promise<TriggerResult> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    throw FunctionalError('Entity not found', { entityId });
  }

  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  // Task 7: resolve scope from the entity's own currently-assigned status, not a hardcoded Global default.
  const scope = await resolveStatusScope(context, user, (entity as BasicStoreEntity).x_opencti_workflow_id);
  const definitionData = await getDefinitionData(context, user, entitySetting, false, scope);
  if (!definitionData) {
    return {
      success: false,
      reason: `Workflows are not configured for entity type: ${entity.entity_type}`,
    };
  }

  try {
    const executionContext = bypassDraftContext(context);
    const executionUser = executionContext.user!;

    const instanceEntity = await ensureWorkflowInstance(executionContext, executionUser, entity, entitySetting, definitionData);

    if (instanceEntity.pendingStatus === 'pending') {
      return {
        success: false,
        reason: 'A workflow transition is already pending for this entity. Wait for it to complete, retry the failed action, or ask an admin to clear the pending state.',
      };
    }

    const targetStatus = await storeLoadById<BasicWorkflowStatus>(executionContext, executionUser, targetStatusId, ENTITY_TYPE_STATUS);
    const targetState = targetStatus ? (definitionData.states ?? []).find((s) => s.statusId === targetStatus.template_id) : undefined;
    if (!targetState) {
      return {
        success: false,
        reason: `Status "${targetStatusId}" does not map to any state of the published workflow`,
      };
    }

    const currentStateId = instanceEntity.currentState;
    const instanceId = instanceEntity.internal_id || instanceEntity.id;

    if (applyTransitionActions) {
      const definition = WorkflowFactory.createDefinition(definitionData);
      const workflowContext = {
        entity,
        user: WORKFLOW_MANAGER_USER,
        triggeringUser: executionUser,
        context: executionContext,
        runtimeParams: {},
        __createListTask: createListTask,
        __workflowInstanceId: instanceId,
        __draftEntityIds: [],
      };
      const currentStateDef = definition.getStateDefinition(currentStateId);
      for (const hook of currentStateDef?.onExit ?? []) {
        await hook(workflowContext);
      }
      const targetStateDef = definition.getStateDefinition(targetState.statusId);
      for (const hook of targetStateDef?.onEnter ?? []) {
        await hook(workflowContext);
      }
    }

    let history: any[];
    try {
      history = JSON.parse(instanceEntity.history || '[]');
    } catch {
      history = [];
    }
    history = appendWorkflowHistoryEntry(history, {
      state: targetState.statusId,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: 'event_bypass',
      ...(comment ? { comment } : {}),
      ...(closingReason ? { closing_reason: closingReason } : {}),
    });

    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'currentState', value: [targetState.statusId] },
      { key: 'history', value: [JSON.stringify(history)] },
    ]);

    // Keep the legacy `x_opencti_workflow_id` in sync with the new state (same as triggerWorkflowEvent).
    await projectWorkflowState(executionContext, entity as BasicStoreEntity, targetState.statusId, resolveProjectionScope(instanceEntity.scope));

    const workflowInstance = await getWorkflowInstance(context, user, entityId);
    if (comment?.trim()) {
      await notifyWorkflowTransitionComment(executionContext, entity as BasicStoreEntity, 'event_bypass', comment, user.id);
    }

    return { success: true, newState: targetState.statusId, executionStatus: 'completed', instance: workflowInstance, entity };
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      reason: `Workflow bypass update failed: ${reason}`,
    };
  }
};

/**
 * Initialize the workflow instance for a newly created entity and fire the
 * onEnter hooks of the initial state. No-op if no workflow is configured for
 * the entity type or if an instance already exists.
 */
/**
 * Task 7: detects which WorkflowDefinition scope a `Status` id belongs to. Scope is a property
 * of the `Status` itself (its own `scope` field), not something the caller declares separately —
 * so any caller resolving a request_access-scoped Status id (e.g. an entity's current
 * `x_opencti_workflow_id`, or a status being written to it) is routed correctly, with no
 * entity-type-specific hardcoding. Defaults to `StatusScope.Global` when no status id is supplied,
 * or when the supplied status cannot be found.
 */
const resolveStatusScope = async (
  context: AuthContext,
  user: AuthUser,
  statusId?: string,
): Promise<StatusScope> => {
  if (!statusId) return StatusScope.Global;
  const status = await storeLoadById<BasicWorkflowStatus>(context, user, statusId, ENTITY_TYPE_STATUS);
  return status?.scope ?? StatusScope.Global;
};

/**
 * Task 7, Step 1.4: thin wrapper of `resolveStatusScope` for the entity-creation call site — so
 * any caller that supplies a request_access-scoped Status id at creation (e.g.
 * requestAccess-domain.ts's CaseRfi creation) is routed correctly, with no entity-type-specific
 * hardcoding.
 */
const resolveEntityCreationScope = async (
  context: AuthContext,
  user: AuthUser,
  entity: { x_opencti_workflow_id?: string },
): Promise<StatusScope> => resolveStatusScope(context, user, entity.x_opencti_workflow_id);

export const initializeEntityWorkflow = async (
  context: AuthContext,
  user: AuthUser,
  entity: any,
): Promise<void> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const entitySetting = await getWorkflowConfig(executionContext, executionUser, entity.entity_type);
  const scope = await resolveEntityCreationScope(executionContext, executionUser, entity);
  const definitionData = await getDefinitionData(executionContext, executionUser, entitySetting, false, scope);
  if (!definitionData) return;
  await ensureWorkflowInstance(executionContext, executionUser, entity, entitySetting, definitionData);
};

let workflowLifecycleHooksRegistered = false;

/**
 * Task 8: reacts to a direct/concurrent write of `x_opencti_workflow_id` — any writer other than
 * the workflow engine's own projection (`projectWorkflowState`, marked `workflowInternalWrite` and
 * filtered out before this hook chain runs, see `middleware.ts`'s `updateAttribute`) — keeping the
 * entity's `WorkflowInstance` in sync. Registered into the shared post-attribute-update hook
 * registry so it fires generically for every such writer: playbooks
 * (`manipulate-knowledge-component.ts`), mass/background operations, the public GraphQL API, and
 * the sync manager.
 *
 * Step 3.4 write-path audit: the only other direct writer of `x_opencti_workflow_id` found in this
 * codebase is `requestAccess-domain.ts`, which sets it at entity *creation* time (not via
 * `updateAttribute`) — that path never reaches this hook, and does not need to: Task 3's
 * `initializeEntityWorkflow` (fired by the post-entity-creation hook) already resolves that same
 * supplied status at creation time via `resolveSuppliedStatus`, so the instance starts in the
 * correct state without this hook's involvement. No other direct-write path outside
 * `updateAttribute` was found.
 */
export const syncWorkflowInstanceFromExternalWrite = async (
  context: AuthContext,
  entity: Record<string, any>,
  newStatusId: string,
): Promise<void> => {
  const executionContext = { ...bypassDraftContext(context), user: WORKFLOW_MANAGER_USER };

  // Task 7: the written status's own scope determines which WorkflowDefinition applies (e.g. a
  // RequestAccess-scoped status written by requestAccess-domain.ts), not a hardcoded Global default.
  const status = await storeLoadById<BasicWorkflowStatus>(executionContext, WORKFLOW_MANAGER_USER, newStatusId, ENTITY_TYPE_STATUS);
  const scope = status?.scope ?? StatusScope.Global;

  // Step 0.6: gated by published-workflow existence, not by any UI-only feature flag.
  const entitySetting = await getWorkflowConfig(executionContext, WORKFLOW_MANAGER_USER, entity.entity_type);
  const definitionData = await getDefinitionData(executionContext, WORKFLOW_MANAGER_USER, entitySetting, false, scope);
  if (!definitionData) return;

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(executionContext, WORKFLOW_MANAGER_USER, effectiveEntityId);
  // No instance yet: nothing to sync onto. The next read via getWorkflowInstance lazily
  // backfills one (Task 3) at the definition's initialState.
  if (!instanceEntity) return;

  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  const matchedState = status ? (definitionData.states ?? []).find((s) => s.statusId === status.template_id) : undefined;

  if (!matchedState) {
    // Unmapped-status write policy: keep the write, do not guess a nearest state, do not reject —
    // just surface a diagnostic and leave currentState untouched.
    await updateAttribute(executionContext, WORKFLOW_MANAGER_USER, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'pendingError', value: [`Direct write set x_opencti_workflow_id to Status "${newStatusId}", which does not map to any state of the published workflow`] },
    ]);
    return;
  }

  if (matchedState.statusId === instanceEntity.currentState) {
    // Already at the mapped state: idempotent no-op, nothing to record.
    return;
  }

  let history: any[];
  try {
    history = JSON.parse(instanceEntity.history || '[]');
  } catch {
    history = [];
  }
  history = appendWorkflowHistoryEntry(history, {
    state: matchedState.statusId,
    user_id: WORKFLOW_MANAGER_USER.id,
    timestamp: now(),
    event: 'event_external',
  });

  await updateAttribute(executionContext, WORKFLOW_MANAGER_USER, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
    { key: 'currentState', value: [matchedState.statusId] },
    { key: 'history', value: [JSON.stringify(history)] },
    { key: 'pendingError', value: [null] },
  ]);
};

/**
 * Task 6, Step 3.4: on republish (a definition that already had a `published_version` before this
 * call — never the entity type's very first-ever publish), reconciles any entity whose
 * `x_opencti_workflow_id` was written directly while workflow mechanics were inactive (e.g. during
 * a rollback window where `EntitySetting.workflow_id` had been cleared, per Step 3.3's rollback
 * guidance — both read-repair and this module's own external-write sync no-op without a published
 * definition). Without this, the next ordinary read would trigger read-repair (instance wins) and
 * silently discard that legitimate external write — the opposite direction from
 * `syncWorkflowInstanceFromExternalWrite`'s own handling (status wins). Last-write-wins: only
 * entities whose own `updated_at` is strictly newer than their `WorkflowInstance`'s `updated_at`
 * are reconciled (status wins for those); an instance already at least as fresh is left untouched,
 * since read-repair remains correct for it.
 *
 * Known cost (per Step 3.5): a full scan of all entities of `entityType`, run once per republish —
 * acceptable for the infrequent, admin-triggered republish/re-enable operation, unlike the hot
 * per-entity-creation path Step 3.5 is concerned with.
 */
const reconcileExternalWritesOnRepublish = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<void> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const entities = await fullEntitiesList<BasicStoreEntity & { x_opencti_workflow_id?: string }>(
    executionContext,
    executionUser,
    [entityType],
  );

  for (const entity of entities) {
    if (!entity.x_opencti_workflow_id) continue;

    const effectiveEntityId = entity.internal_id || entity.id;
    const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
    // No instance yet: nothing to reconcile — the next read lazily backfills one (Task 3).
    if (!instanceEntity) continue;

    const entityUpdatedAt = entity.updated_at ? new Date(entity.updated_at).getTime() : 0;
    const instanceUpdatedAt = instanceEntity.updated_at ? new Date(instanceEntity.updated_at).getTime() : 0;
    // Instance at least as fresh as the entity: read-repair's instance-wins direction is already
    // correct for it, nothing to reconcile.
    if (entityUpdatedAt <= instanceUpdatedAt) continue;

    try {
      await syncWorkflowInstanceFromExternalWrite(executionContext, entity, entity.x_opencti_workflow_id);
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Failed to reconcile external write on republish', { cause: error, entityId: effectiveEntityId, entityType });
    }
  }
};

/**
 * Registers this module's post-entity-creation side effects (eager `WorkflowInstance`
 * initialization) into the decoupled hook registry in `entity-lifecycle-hooks.ts`. Must be
 * called exactly once from the server's central bootstrap sequence (`boot.ts`), before any
 * mutation handling begins — guarded here so repeated calls (e.g. from multiple module import
 * paths) are safe no-ops.
 */
export const registerWorkflowLifecycleHooks = (): void => {
  if (workflowLifecycleHooksRegistered) return;
  registerPostEntityCreationHook(initializeEntityWorkflow);
  registerPostAttributeUpdateHook(async (context, _user, entity, _field, newValue) => {
    await syncWorkflowInstanceFromExternalWrite(context, entity, newValue);
  });
  workflowLifecycleHooksRegistered = true;
};

/** Test-only: resets the idempotency guard so tests can exercise registration from a clean state. */
export const __resetWorkflowLifecycleHooksRegisteredForTest = (): void => {
  workflowLifecycleHooksRegistered = false;
};

export const isStatusTemplateUsedInWorkflows = async (
  context: AuthContext,
  user: AuthUser,
  statusTemplateId: string,
): Promise<boolean> => {
  const executionContext = bypassDraftContext(context);
  const workflows = await fullEntitiesList<WorkflowDefinitionEntity>(
    executionContext,
    executionContext.user!,
    [ENTITY_TYPE_WORKFLOW_DEFINITION],
  );
  for (const workflow of workflows) {
    // Check both published and draft versions
    const versions = [workflow.published_version, workflow.draft_version].filter((v): v is WorkflowVersion => v !== undefined && v !== null);
    for (const version of versions) {
      const content = version.content;
      let parsed;
      try {
        parsed = typeof content === 'string' ? JSON.parse(content) : content;
      } catch (_error) {
        // Malformed content is not this function's concern; skip rather than false-positive.
        continue;
      }
      const states: Array<{ statusId?: string }> = parsed?.states ?? [];
      if (states.some((state) => state.statusId === statusTemplateId)) {
        return true;
      }
    }
  }
  return false;
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
  const executionUser = executionContext.user!;
  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
  if (!instanceEntity) throw FunctionalError('No workflow instance found for entity', { entityId });

  let historyArr: any[];
  try {
    historyArr = JSON.parse(instanceEntity.history || '[]');
  } catch {
    historyArr = [];
  }
  historyArr.push({
    state: instanceEntity.currentState,
    user_id: user.id,
    timestamp: new Date().toISOString(),
    event: 'admin_clear_pending_state',
    note: 'Admin force-cleared pending workflow transition state',
  });

  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
    { key: 'pendingStatus', value: [null] },
    { key: 'pendingError', value: [null] },
    { key: 'pendingTransition', value: [null] },
    { key: 'history', value: [JSON.stringify(historyArr)] },
  ]);

  return getWorkflowInstance(context, user, entityId);
};
