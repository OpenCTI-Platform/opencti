import { ENTITIES_WORKFLOW_FEATURE_FLAG, isFeatureEnabled } from '../../../config/conf';
import { StatusScope } from '../../../generated/graphql';
import type { AuthContext, AuthUser } from '../../../types/user';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../case/case-rfi/case-rfi-types';
import type { BasicStoreEntityEntitySetting } from '../../entitySetting/entitySetting-types';
import { getDefinitionData, getWorkflowConfig, type WorkflowDefinitionResponse } from './workflow-domain';

/**
 * The request-access workflow of Case-Rfi, or null when requests run on the legacy flow: it takes
 * ENTITIES_WORKFLOW on and a request-access definition published.
 */
export const getRequestAccessWorkflow = async (
  context: AuthContext,
  user: AuthUser,
): Promise<{ entitySetting: BasicStoreEntityEntitySetting; definitionData: WorkflowDefinitionResponse } | null> => {
  if (!isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
    return null;
  }
  const entitySetting = await getWorkflowConfig(context, user, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (!entitySetting) {
    return null;
  }
  const definitionData = await getDefinitionData(context, user, entitySetting, false, StatusScope.RequestAccess);
  return definitionData ? { entitySetting, definitionData } : null;
};

/** Id of the state marked as the Approved / Declined outcome of the definition. */
export const findOutcomeState = (
  definitionData: Pick<WorkflowDefinitionResponse, 'states'>,
  outcome: 'APPROVED' | 'DECLINED',
): string | undefined => {
  return definitionData.states?.find((state) => state.requestAccessOutcome === outcome)?.statusId;
};
