import { ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled, logApp } from '../../../config/conf';
import { UnsupportedError } from '../../../config/errors';
import { extractEntityRepresentativeName } from '../../../database/entity-representative';
import { updateAttribute } from '../../../database/middleware';
import { internalLoadById } from '../../../database/middleware-loader';
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
 * Records the decision once the RFI has entered its outcome state: request status, audit, applicant
 * notification and decision counter. The state and the share are already persisted, so a failure
 * here is logged and never fails the transition.
 */
export const applyRequestAccessOutcome = async (
  context: AuthContext,
  user: AuthUser,
  rfi: BasicStoreEntityCaseRfi,
  outcome: RequestAccessOutcome,
): Promise<void> => {
  try {
    const action: RequestAccessAction = JSON.parse(rfi.x_opencti_request_access);
    const requestAccessAction: RequestAccessAction = { ...action, status: outcome, executionDate: new Date() };
    await updateAttribute(context, user, rfi.internal_id ?? rfi.id, ENTITY_TYPE_CONTAINER_CASE_RFI, [
      { key: 'x_opencti_request_access', value: [JSON.stringify(requestAccessAction)] },
    ], { workflowInternalWrite: true });
    const requestedEntity = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, (action.entities ?? [])[0]);
    const mainRepresentative = extractEntityRepresentativeName(requestedEntity);
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'update',
      event_access: 'administration',
      message: `${outcome === 'APPROVED' ? 'approved' : 'declined'} demand of request access for entity ${mainRepresentative}`,
      context_data: { id: user.id, entity_type: ENTITY_TYPE_CONTAINER_CASE_RFI, input: requestAccessAction },
    });
    await notifyRequestAccessResult(context, user, requestedEntity, action.applicant_id, mainRepresentative, ActionStatus[outcome]);
    if (outcome === 'APPROVED') {
      addRequestAccessApprovedCount();
    } else {
      addRequestAccessDeclinedCount();
    }
  } catch (error) {
    logApp.error('[OPENCTI-MODULE][Request access] Failed to record the request decision', { cause: error, id: rfi.id, outcome });
  }
};
