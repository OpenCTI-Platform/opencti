import { ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled, logApp } from '../../../config/conf';
import { UnsupportedError } from '../../../config/errors';
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
import { getDefinitionData, getWorkflowConfig, type WorkflowDefinitionResponse } from './workflow-domain';

export type RequestAccessOutcome = 'APPROVED' | 'DECLINED';

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
 * here is logged and never fails the transition; each step after the status write runs on its own.
 */
export const applyRequestAccessOutcome = async (
  context: AuthContext,
  user: AuthUser,
  rfi: BasicStoreEntityCaseRfi,
  outcome: RequestAccessOutcome,
): Promise<void> => {
  const rfiId = rfi.internal_id ?? rfi.id;
  let requestAccessAction: RequestAccessAction;
  try {
    // Read the request fresh: the RFI handed in can predate the transition lock, and the patch rewrites the whole JSON.
    const currentRfi = await storeLoadById<BasicStoreEntityCaseRfi>(context, SYSTEM_USER, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI);
    if (!currentRfi) {
      throw UnsupportedError('Request access RFI not found', { id: rfiId });
    }
    const action: RequestAccessAction = JSON.parse(currentRfi.x_opencti_request_access);
    requestAccessAction = { ...action, status: outcome, executionDate: new Date() };
    await updateAttribute(context, user, rfiId, ENTITY_TYPE_CONTAINER_CASE_RFI, [
      { key: 'x_opencti_request_access', value: [JSON.stringify(requestAccessAction)] },
    ], { workflowInternalWrite: true });
  } catch (error) {
    logApp.error('[OPENCTI-MODULE][Request access] Failed to record the request decision', { cause: error, id: rfiId, outcome });
    return;
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
};
