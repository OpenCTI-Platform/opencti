import { randomUUID } from 'node:crypto';
import { logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { loadAssignees, loadParticipants } from '../../../database/members';
import { createEntity, createRelation, deleteElementById, loadEntity, updateAttribute } from '../../../database/middleware';
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
import type { BasicStoreCommon, BasicStoreEntity, BasicWorkflowStatus, BasicWorkflowTemplateEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { SYSTEM_USER, WORKFLOW_MANAGER_USER } from '../../../utils/access';
import { bypassDraftContext, getDraftContext } from '../../../utils/draftContext';
import { now } from '../../../utils/format';
import { DRAFT_OPERATION_UPDATE_LINKED } from '../../draftWorkspace/draftOperations';
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
import { computeStateOrder } from './workflow-ordering';
import { type ConvertStatusToDefinitionResult, convertStatusToDefinition } from '../migration/status-to-definition-converter';


// EE-only action types – conditions on transitions and onEnter/onExit state actions.
// 'validateDraft' is a CE feature and must NOT be listed here.
const EE_ONLY_ACTION_TYPES = new Set<WorkflowActionConfig['type']>(['updateAuthorizedMembers', 'shareWithOrganizations', 'unshareFromOrganizations', 'asyncBulkAction']);
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
}

const getWorkflowConfig = async (
  context: AuthContext,
  user: AuthUser,
  targetType: string,
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  const executionContext = bypassDraftContext(context);
  return findEntitySettingByType(executionContext, bypassDraftUser(user), targetType);
};

/**
 * Get workflow definition data based on allowDraft parameter.
 */
const getDefinitionData = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  allowDraft: boolean = false,
): Promise<WorkflowDefinitionResponse | null> => {
  if (!entitySetting) return null;

  if (entitySetting.workflow_id) {
    const executionContext = bypassDraftContext(context);
    const workflowDefinitionEntity = await storeLoadById(
      executionContext,
      bypassDraftUser(user),
      entitySetting.workflow_id,
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

const initializeWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { id?: string; internal_id?: string },
  entitySetting: BasicStoreEntityEntitySetting,
  definitionData: WorkflowDefinitionResponse,
): Promise<WorkflowInstanceStoreEntity> => {
  const initialState = definitionData.initialState;
  const entityId = entity.id || entity.internal_id;
  const instanceInput = {
    entity_id: entityId,
    workflow_id: entitySetting.workflow_id || 'manual',
    currentState: initialState,
    history: JSON.stringify([{
      state: initialState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: 'initialization',
    }]),
  };
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
  const instance = await createEntity(executionContext, executionUser, instanceInput, ENTITY_TYPE_WORKFLOW_INSTANCE) as WorkflowInstanceStoreEntity;

  await createRelation(executionContext, executionUser, {
    fromId: entityId,
    toId: instance.id || instance.internal_id,
    relationship_type: RELATION_HAS_WORKFLOW,
  });

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
): Promise<WorkflowDefinitionResponse | null> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  return getDefinitionData(context, user, entitySetting, allowDraft);
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
): Promise<string | null> => {
  if (!entitySetting.workflow_id) return null;
  const executionContext = bypassDraftContext(context);
  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    bypassDraftUser(user),
    entitySetting.workflow_id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  return workflowDefinitionEntity?.published_version?.id ?? null;
};

/**
 * Read-only preview of what migrating an entity type's legacy `Status` set to a
 * `WorkflowDefinition` would produce, one result per `StatusScope` present — no persisted
 * changes. Pure conversion logic lives in `convertStatusToDefinition`; this just gathers the
 * `Status`/`StatusTemplate` input data for `entityType` (all scopes, matching `byScope`'s shape).
 */
export const getWorkflowMigrationPreview = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<ConvertStatusToDefinitionResult> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);
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
 * Create or update workflow definition for an entity type.
 */
export const setWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definition: string,
): Promise<EntitySettingWithWorkflowResponse> => {
  validateSetting(entityType, 'workflow_id');

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

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const errors = await validateWorkflowDefinitionData(executionContext, executionUser, definition, entityType, entitySetting.workflow_id ?? undefined);

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
  if (entitySetting.workflow_id) {
    const existingWorkflow = await storeLoadById(
      executionContext,
      executionUser,
      entitySetting.workflow_id,
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
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (entitySetting?.workflow_id) {
    const executionContext = bypassDraftContext(context);
    const { element } = await updateAttribute(executionContext, bypassDraftUser(user), entitySetting.id, 'EntitySetting', [
      { key: 'workflow_id', value: [null] },
    ]);
    return element as unknown as BasicStoreEntityEntitySetting;
  }
  return entitySetting;
};

/**
 * Ensures every workflow state's `statusId` (StatusTemplate reference) has a matching `Status`
 * record for this entity type in the Global scope, creating any that are missing.
 *
 * Only the Global scope is reconciled here — existing `Status` records in other scopes are
 * left untouched.
 */
export const ensureFullStatusMapping = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definitionData: WorkflowDefinitionData,
): Promise<void> => {
  const states = definitionData.states ?? [];
  if (states.length === 0) return;

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const existingStatuses = await fullEntitiesList<BasicWorkflowStatus>(executionContext, executionUser, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [entityType] },
        { key: ['scope'], values: [StatusScope.Global] },
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
      scope: StatusScope.Global,
    });
  }
};

// Grace period before an orphaned Status is eligible for hard deletion by the cleanup manager.
const STATUS_DELETION_GRACE_PERIOD_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * True if any entity of `entityType` currently has its legacy `x_opencti_workflow_id` field
 * pointing at this `Status`, either in the live index or inside any draft (across all drafts,
 * not just one) — a `Status` referenced only from within a draft must not be deleted, since
 * publishing that draft later would leave it pointing at a hard-deleted record.
 */
const isStatusReferencedByEntity = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  statusId: string,
): Promise<boolean> => {
  const statusFilters = {
    mode: FilterMode.And,
    filters: [{ key: ['x_opencti_workflow_id'], values: [statusId] }],
    filterGroups: [],
  };
  const entities = await fullEntitiesList<any>(context, user, [entityType], { filters: statusFilters });
  if (entities.length > 0) return true;

  const draftEntities = await fullEntitiesList<any>(context, user, [entityType], {
    indices: [READ_INDEX_DRAFT_OBJECTS],
    filters: statusFilters,
  });
  return draftEntities.length > 0;
};

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
): Promise<void> => {
  const oldTemplateIds = new Set((oldDefinitionData.states ?? []).map((s) => s.statusId).filter((id): id is string => !!id));
  const newTemplateIds = new Set((newDefinitionData.states ?? []).map((s) => s.statusId).filter((id): id is string => !!id));

  const existingStatuses = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [entityType] },
        { key: ['scope'], values: [StatusScope.Global] },
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
  const definitionData = await getWorkflowDefinition(context, user, status.type, false);
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
): Promise<EntitySettingWithWorkflowResponse> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  if (!entitySetting.workflow_id) {
    throw FunctionalError('No workflow definition to publish', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    entitySetting.workflow_id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: entitySetting.workflow_id });
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
    entitySetting.workflow_id,
  );
  if (freshValidationErrors.length > 0) {
    throw FunctionalError('Cannot publish workflow with validation errors', {
      entityType,
      errorCount: freshValidationErrors.length,
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
      await reconcileOrphanedStatuses(executionContext, executionUser, entityType, oldDef, newDef);
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
    await ensureFullStatusMapping(executionContext, executionUser, entityType, publishedDefinitionData);
  }

  // CONSISTENCY GUARANTEE: published_version will be in all_versions (already there via draft)
  // Copy draft_version to published_version and clear the draft (no more unpublished changes).
  const updates: EditInput[] = [
    { key: 'published_version', value: [draftVersion] },
    { key: 'draft_version', value: [] },
  ];

  await updateAttribute(executionContext, executionUser, workflowDefinitionEntity.id, ENTITY_TYPE_WORKFLOW_DEFINITION, updates);

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
    workflow_id: entitySettingWithWorkflow.workflow_id,
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
): Promise<EntitySettingWithWorkflowResponse> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  if (!entitySetting.workflow_id) {
    throw FunctionalError('No workflow definition found', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = bypassDraftUser(user);

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    entitySetting.workflow_id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: entitySetting.workflow_id });
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
    workflow_id: entitySettingWithWorkflow.workflow_id,
    target_type: entitySettingWithWorkflow.target_type,
    errors: [],
    published: true,
  } as EntitySettingWithWorkflowResponse;
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

  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = await getDefinitionData(context, user, entitySetting);
  if (!definitionData) {
    return null;
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(context, user, effectiveEntityId);
  const currentState = instanceEntity?.currentState ?? definitionData.initialState;

  // Pass entitySetting and definitionData to avoid redundant lookups in getAllowedTransitions
  const allowedTransitions = await getAllowedTransitions(context, user, entityId, { entity, entitySetting, definitionData, instanceEntity });
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
  };
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
  },
): Promise<Array<{ event: string; toState: string; comment?: string; actions: string[]; requiresShareOrganizationInput: boolean; requiresUnshareOrganizationInput: boolean }>> => {
  const entity = options?.entity ?? await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return [];
  }

  const entitySetting = options?.entitySetting ?? await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = options?.definitionData ?? await getDefinitionData(context, user, entitySetting);

  if (!definitionData) {
    return [];
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = options?.instanceEntity ?? await findWorkflowInstanceEntity(context, user, effectiveEntityId);
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
        actions: transition.actionTypes || [],
        requiresShareOrganizationInput: transition.requiresShareOrganizationInput ?? false,
        requiresUnshareOrganizationInput: transition.requiresUnshareOrganizationInput ?? false,
      };
    }),
  )).filter((t): t is NonNullable<typeof t> => t !== null);

  return resolvedTransitions;
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
 * @returns {Promise<TriggerResult>} The result of the trigger
 */
export const triggerWorkflowEvent = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  eventName: string,
  comment?: string,
  runtimeParams: Record<string, unknown> = {},
): Promise<TriggerResult> => {
  // 1. Fetch the entity
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    throw FunctionalError('Entity not found', { entityId });
  }

  // 2. Fetch its EntitySetting to get the workflow configuration
  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = await getDefinitionData(context, user, entitySetting);

  if (!definitionData) {
    return {
      success: false,
      reason: `Workflows are not configured for entity type: ${entity.entity_type}`,
    };
  }

  try {
    const executionContext = bypassDraftContext(context);
    const executionUser = bypassDraftUser(user);

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

    history.push({
      state: newState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: eventName,
      ...(comment ? { comment } : {}),
    });

    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'currentState', value: [newState] },
      { key: 'history', value: [JSON.stringify(history)] },
    ]);

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
  const definitionData = await getDefinitionData(executionContext, executionUser, entitySetting);
  if (!definitionData) return;
  await ensureWorkflowInstance(executionContext, executionUser, entity, entitySetting, definitionData);
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
  const executionUser = bypassDraftUser(user);
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
