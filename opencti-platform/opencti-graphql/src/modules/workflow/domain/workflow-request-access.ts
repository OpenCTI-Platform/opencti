import { ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled, logApp } from '../../../config/conf';
import { FunctionalError, UnsupportedError } from '../../../config/errors';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { updateAttribute } from '../../../database/middleware';
import { internalLoadById, storeLoadById } from '../../../database/middleware-loader';
import { StatusScope } from '../../../generated/graphql';
import { publishUserAction } from '../../../listener/UserActionListener';
import { addRequestAccessApprovedCount, addRequestAccessDeclinedCount } from '../../../manager/telemetryManager';
import type { BasicStoreEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { SYSTEM_USER } from '../../../utils/access';
import { type BasicStoreEntityCaseRfi, ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../case/case-rfi/case-rfi-types';
import type { BasicStoreEntityEntitySetting } from '../../entitySetting/entitySetting-types';
import { ActionStatus, isUserCanActionRequestAccess, notifyRequestAccessResult, type RequestAccessAction } from '../../requestAccess/requestAccess-domain';
import type { TriggerResult } from '../types/workflow-types';
import {
  getAllowedTransitions,
  getDefinitionData,
  getWorkflowConfig,
  resolveRequestAccessWorkflowState,
  triggerWorkflowEvent,
  type WorkflowDefinitionResponse,
} from './workflow-domain';

export type RequestAccessOutcome = 'APPROVED' | 'DECLINED';

const DECISION_WRITE_ATTEMPTS = 3;

/**
 * The request-access workflow of Case-Rfi, or null when requests run on the legacy flow: it takes
 * ENTITIES_WORKFLOW on and a request-access definition published. Read as the system: requesters
 * are ordinary users, and one who cannot read the definition must not be silently moved to the legacy flow.
 */
export const getRequestAccessWorkflow = async (
  context: AuthContext,
  _user: AuthUser,
): Promise<{ entitySetting: BasicStoreEntityEntitySetting; definitionData: WorkflowDefinitionResponse } | null> => {
  if (!isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
    return null;
  }
  const entitySetting = await getWorkflowConfig(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (!entitySetting) {
    return null;
  }
  const definitionData = await getDefinitionData(context, SYSTEM_USER, entitySetting, false, StatusScope.RequestAccess);
  return definitionData ? { entitySetting, definitionData } : null;
};

/** Whether the request of an RFI is decided on the published request-access workflow rather than the legacy flow. */
export const isWorkflowDrivenRequestAccess = async (context: AuthContext, rfiId: string): Promise<boolean> => {
  const rfi = await storeLoadById<BasicStoreEntityCaseRfi>(context, SYSTEM_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI);
  return !!rfi && !!await resolveRequestAccessWorkflowState(context, rfi);
};

/** Id of the state marked as the Approved / Declined outcome of the definition. */
export const findOutcomeState = (
  definitionData: Pick<WorkflowDefinitionResponse, 'states'>,
  outcome: RequestAccessOutcome,
): string | undefined => {
  return definitionData.states?.find((state) => state.requestAccessOutcome === outcome)?.statusId;
};

/** Outcome marked on a state of the definition, if any. */
export const findStateOutcome = (
  definitionData: Pick<WorkflowDefinitionResponse, 'states'>,
  stateId: string | null | undefined,
): RequestAccessOutcome | undefined => {
  if (!stateId) return undefined;
  return definitionData.states?.find((state) => state.statusId === stateId)?.requestAccessOutcome;
};

/** Entering an outcome state decides the request: the caller needs the rights of the legacy approve and decline. */
export const assertCanEnterRequestAccessOutcome = async (
  context: AuthContext,
  user: AuthUser,
  rfi: BasicStoreEntityCaseRfi,
): Promise<void> => {
  if (!await isUserCanActionRequestAccess(context, user, rfi)) {
    throw UnsupportedError('You need to be able to edit the RFI and share knowledge', { id: rfi.id });
  }
};

/**
 * Records the decision once the RFI has entered its outcome state: request status and decision counter,
 * then audit and applicant notification. The state and the share are already persisted, so a failure
 * never fails the transition; each step after the status write runs on its own. The status write is retried,
 * and returns false when it still fails: the caller flags the workflow instance, as the RFI is decided while
 * its request still reads NEW.
 */
export const applyRequestAccessOutcome = async (
  context: AuthContext,
  user: AuthUser,
  rfi: BasicStoreEntityCaseRfi,
  outcome: RequestAccessOutcome,
): Promise<boolean> => {
  const rfiId = rfi.internal_id ?? rfi.id;
  let requestAccessAction: RequestAccessAction | undefined;
  for (let attempt = 1; attempt <= DECISION_WRITE_ATTEMPTS && !requestAccessAction; attempt += 1) {
    try {
      // Read the request fresh: the RFI handed in can predate the transition lock, and the patch rewrites the whole JSON.
      const currentRfi = await storeLoadById<BasicStoreEntityCaseRfi>(context, SYSTEM_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI);
      if (!currentRfi) {
        throw UnsupportedError('Request access RFI not found', { id: rfiId });
      }
      const action: RequestAccessAction = JSON.parse(currentRfi.x_opencti_request_access);
      const decided = { ...action, status: outcome, executionDate: new Date() };
      await updateAttribute(context, user, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI, [
        { key: 'x_opencti_request_access', value: [JSON.stringify(decided)] },
      ], { workflowInternalWrite: true });
      requestAccessAction = decided;
    } catch (error) {
      logApp.error('[OPENCTI-MODULE][Request access] Failed to record the request decision', { cause: error, id: rfiId, outcome, attempt });
    }
  }
  if (!requestAccessAction) {
    return false;
  }
  if (outcome === 'APPROVED') {
    addRequestAccessApprovedCount();
  } else {
    addRequestAccessDeclinedCount();
  }
  const requestedEntityId = (requestAccessAction.entities ?? [])[0];
  let requestedEntity: BasicStoreEntity | undefined;
  let mainRepresentative = requestedEntityId;
  try {
    requestedEntity = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, requestedEntityId);
    mainRepresentative = extractEntityRepresentativeName(requestedEntity);
  } catch (error) {
    logApp.error('[OPENCTI-MODULE][Request access] Failed to load the requested entity', { cause: error, id: rfiId, requestedEntityId });
  }
  try {
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `${outcome === 'APPROVED' ? 'approved' : 'declined'} demand of request access for entity ${mainRepresentative}`,
      context_data: { id: user.id, entity_type: ENTITY_TYPE_CONTAINER_CASE_RFI, input: requestAccessAction },
    });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE][Request access] Failed to audit the request decision', { cause: error, id: rfiId, outcome });
  }
  try {
    if (!requestedEntity) {
      throw UnsupportedError('Requested entity not found', { requestedEntityId });
    }
    await notifyRequestAccessResult(context, user, requestedEntity, requestAccessAction.applicant_id, mainRepresentative, ActionStatus[outcome]);
  } catch (error) {
    logApp.error('[OPENCTI-MODULE][Request access] Failed to notify the applicant of the request decision', { cause: error, id: rfiId, outcome });
  }
  return true;
};

/**
 * Decides a workflow-driven request through the transition allowed from its current state into the outcome
 * state. A transition that needs a comment is left to the UI, which can ask for it.
 */
export const fireRequestAccessOutcomeTransition = async (
  context: AuthContext,
  user: AuthUser,
  rfiId: string,
  outcome: RequestAccessOutcome,
): Promise<TriggerResult> => {
  const rfi = await storeLoadById<BasicStoreEntityCaseRfi>(context, SYSTEM_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI);
  const workflowState = rfi ? await resolveRequestAccessWorkflowState(context, rfi) : null;
  if (!workflowState) {
    throw FunctionalError('This request access is not decided on a request access workflow', { id: rfiId });
  }
  const { definitionData, instanceEntity, currentState } = workflowState;
  const outcomeState = findOutcomeState(definitionData, outcome);
  const allowedTransitions = outcomeState ? await getAllowedTransitions(context, user, rfiId, { definitionData, instanceEntity, currentState }) : [];
  const transition = allowedTransitions.find((allowedTransition) => allowedTransition.toState === outcomeState);
  if (!transition) {
    throw FunctionalError(`No transition to ${outcome} is allowed from the current state`, { id: rfiId });
  }
  if (transition.comment === 'required') {
    throw FunctionalError('This transition requires a comment', { id: rfiId });
  }
  return triggerWorkflowEvent(context, user, rfiId, transition.event, undefined, {}, undefined, { fromState: currentState });
};

/**
 * Makes the request status follow a state reached by bypass without deciding the request: no share,
 * audit, notification or count. The state is already persisted, so a failure here is only logged.
 */
export const mirrorRequestAccessStatus = async (
  context: AuthContext,
  user: AuthUser,
  rfiId: string,
  status: RequestAccessOutcome | 'NEW',
): Promise<void> => {
  try {
    const currentRfi = await storeLoadById<BasicStoreEntityCaseRfi>(context, SYSTEM_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI);
    if (!currentRfi) {
      throw UnsupportedError('Request access RFI not found', { id: rfiId });
    }
    const action: RequestAccessAction = JSON.parse(currentRfi.x_opencti_request_access);
    if (action.status === status) {
      return;
    }
    await updateAttribute(context, user, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI, [
      { key: 'x_opencti_request_access', value: [JSON.stringify({ ...action, status })] },
    ], { workflowInternalWrite: true });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE][Request access] Failed to record the request status', { cause: error, id: rfiId, status });
  }
};
