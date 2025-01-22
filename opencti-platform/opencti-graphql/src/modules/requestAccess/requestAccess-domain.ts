import type { AuthContext, AuthUser } from '../../types/user';
import { ActionStatus, type CaseRfiAddInput, type EditInput, FilterMode, OrderingMode, type RequestAccessAddInput, StatusOrdering } from '../../generated/graphql';
import { addCaseRfi, findById as findRFIById } from '../case/case-rfi/case-rfi-domain';
import { SYSTEM_USER } from '../../utils/access';
import { listAllEntities } from '../../database/middleware-loader';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { logApp } from '../../config/conf';
import { addOrganizationRestriction } from '../../domain/stix';
import { updateAttribute } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT, INPUT_GRANTED_REFS } from '../../schema/general';
import { findById as findOrganizationById } from '../organization/organization-domain';
import { elLoadById } from '../../database/engine';
import type { BasicStoreBase, BasicWorkflowStatus } from '../../types/store';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { FunctionalError, ValidationError } from '../../config/errors';
import { getEntityFromCache } from '../../database/cache';
import { getEntitySettingFromCache } from '../entitySetting/entitySetting-utils';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import { loadThroughDenormalized } from '../../resolvers/stix';
import type { BasicStoreSettings } from '../../types/settings';

export const REQUEST_SHARE_ACCESS_INFO_TYPE = 'Request sharing';

export interface RequestAccessActionStatus {
  rfiStatusId: string,
  actionStatus: ActionStatus
}

export interface RequestAccessAction {
  reason?: string
  entities?: string[]
  members?: string[]
  type?: string,
  status: string,
  executionDate?: Date,
  workflowMapping: RequestAccessActionStatus[]
}

export const getPlatformOrganization = async (context: AuthContext, user: AuthUser) => {
  const settings: BasicStoreSettings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS); // TODO should we get from cache?
  return settings.platform_organization;
};

export const getRfiEntitySettings = async (context: AuthContext) => {
  return getEntitySettingFromCache(context, ENTITY_TYPE_CONTAINER_CASE_RFI);
};

export const isRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  // 1. EE must be enabled
  const isEEConfigured: boolean = await isEnterpriseEdition(context);
  // 2. Platform organization should be set up
  const platformOrg: boolean = await getPlatformOrganization(context, user) !== undefined;
  // 3. Workflow should be enabled
  const rfiEntitySettings = await getRfiEntitySettings(context);
  const isWorkflowEnabled: boolean = rfiEntitySettings?.workflow_configuration !== undefined;
  // 4. Request access status should be configured
  const areRequestAccessStatusConfigured: boolean = rfiEntitySettings?.request_access_workflow !== undefined
    && rfiEntitySettings.request_access_workflow.declined_workflow_id !== undefined
    && rfiEntitySettings.request_access_workflow.approved_workflow_id !== undefined;
  // 5. Auth member admin should be configured.
  // FIXME uncomment when admin approval configuration is implemented
  const isRequestAccesApprovalAdminConfigured = true; // rfiEntitySettings?.request_access_workflow?.approval_admin !== undefined;
  return isEEConfigured
    && platformOrg
    && isWorkflowEnabled
    && areRequestAccessStatusConfigured
    && isRequestAccesApprovalAdminConfigured;
};

export const checkRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  if (!await isRequestAccessEnabled(context, user)) {
    throw FunctionalError('[OPENCTI-MODULE][Request access] Request access feature is missing configuration.');
  }
};

export const getRFIStatusForAction = async (context: AuthContext, user: AuthUser, action:ActionStatus) => {
  const rfiEntitySettings = await getRfiEntitySettings(context);
  const requestAccessWorkflow = rfiEntitySettings?.request_access_workflow;
  if (requestAccessWorkflow) {
    if (action === ActionStatus.Approved) {
      return requestAccessWorkflow.approved_workflow_id;
    }

    if (action === ActionStatus.Declined) {
      return requestAccessWorkflow.declined_workflow_id;
    }
  }
  return undefined;
};

export const findFirstWorkflowStatus = async (context: AuthContext, user: AuthUser) => {
  const args = {
    orderBy: StatusOrdering.Order,
    orderMode: OrderingMode.Asc,
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['type'], values: [ENTITY_TYPE_CONTAINER_CASE_RFI] }],
      filterGroups: [],
      first: 1
    },
    connectionFormat: false
  };
  const allWorkflowStatus = await listAllEntities<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
  logApp.info('ANGIE allWorkflowStatus', { allWorkflowStatus });
  return allWorkflowStatus[0];
};

export const getRFIStatusMap = async (context: AuthContext, user: AuthUser) => {
  const rfiEntitySettings = await getRfiEntitySettings(context);
  const requestAccessWorkflow = rfiEntitySettings?.request_access_workflow;
  const result : RequestAccessActionStatus[] = [];
  if (requestAccessWorkflow) {
    if (requestAccessWorkflow.approved_workflow_id) {
      result.push({
        rfiStatusId: requestAccessWorkflow.approved_workflow_id,
        actionStatus: ActionStatus.Approved,
      });
    }

    if (requestAccessWorkflow.declined_workflow_id) {
      result.push({
        rfiStatusId: requestAccessWorkflow.declined_workflow_id,
        actionStatus: ActionStatus.Declined,
      });
    }
  }
  if (rfiEntitySettings?.workflow_configuration) {
    const firstStatus = await findFirstWorkflowStatus(context, user);
    result.push({
      rfiStatusId: firstStatus.internal_id,
      actionStatus: ActionStatus.New });
  }

  return result;
};

const computeAuthorizedMembersForRequestAccess = async (context: AuthContext, user: AuthUser, requestAcessEntities: string[]) => {
  const authorizedMembers = [];
  const rfiEntitySettings = await getRfiEntitySettings(context);
  const platformOrganization = await getPlatformOrganization(context, user);
  if (!platformOrganization) {
    throw FunctionalError('This feature requires data segregation by organization. Please contact you administrator.');
  }

  if (rfiEntitySettings && rfiEntitySettings.request_access_workflow) {
    const requestAccessAdmin = rfiEntitySettings.request_access_workflow.approval_admin;
    const grantedOrganizationsIds: string[] = [];
    const entity = await elLoadById(context, user, requestAcessEntities[0]); // TODO remove requestAcessEntities[0]
    const objectOrganizations = await loadThroughDenormalized(context, user, entity, INPUT_GRANTED_REFS);
    objectOrganizations.map((org: any) => grantedOrganizationsIds.push(org.id));

    if (grantedOrganizationsIds.length > 0) {
      grantedOrganizationsIds.map((organizationId) => authorizedMembers.push({
        id: organizationId,
        access_right: 'edit',
      }));
    } else {
    // If no granted organization we use platform organization
      authorizedMembers.push({
        id: platformOrganization,
        access_right: 'edit',
      });
    }

    // set Admin
    authorizedMembers.push({
      id: requestAccessAdmin || platformOrganization, // TODO remove platformOrganization here when settings are done.
      access_right: 'admin',
    });

    return authorizedMembers;
  }
  throw FunctionalError('Please set an approval admin fro request access');
};

/*
const initForDev = async (context: AuthContext) => {
  const statusTemplateDeclined = await createStatusTemplate(context, SYSTEM_USER, { name: 'DECLINED', color: '#b83f13' });
  const statusTemplateApproved = await createStatusTemplate(context, SYSTEM_USER, { name: 'APPROVED', color: '#4caf50' });
  const statusEntityRFIDeclined = await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE, { template_id: statusTemplateDeclined.id, order: 0 });
  const statusEntityRFIApproved = await createStatus(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE, { template_id: statusTemplateApproved.id, order: 0 });

  const initialConfig = {
    workflow: [statusEntityRFIApproved.id, statusEntityRFIDeclined.id],
    approved_workflow_id: statusEntityRFIApproved.id,
    declined_workflow_id: statusEntityRFIDeclined.id,
  };

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);
  if (rfiEntitySettings) {
    logApp.info('ANGIE INIT rfiEntitySettings:', { rfiEntitySettings, initialConfig });
    const editInput = [
      { key: 'request_access_workflow', value: [initialConfig] }
    ];
    // TODO use updateAttribute instead
    // await updateAttribute(context, user, rfiEntitySettings.id, ENTITY_TYPE_ENTITY_SETTING, {request_access_workflow});
    await entitySettingEditField(context, SYSTEM_USER, rfiEntitySettings.id, editInput);
  }
};
 */

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - addRequestAccess', { input });
  await checkRequestAccessEnabled(context, user);
  // await initForDev(context);

  const authorized_members = await computeAuthorizedMembersForRequestAccess(context, user, input.request_access_entities);
  const requestedEntities = input.request_access_entities;
  const allActionStatuses = await getRFIStatusMap(context, user);

  const action: RequestAccessAction = {
    reason: input.request_access_reason || 'no reason',
    members: input.request_access_members,
    type: input.request_access_type?.toString(),
    entities: input.request_access_entities,
    status: ActionStatus.New,
    workflowMapping: allActionStatuses
  };

  const organizationId = input.request_access_members[0];
  const elementId = input.request_access_entities[0];

  const elementData = await elLoadById(context, SYSTEM_USER, elementId) as unknown as BasicStoreBase;
  if (elementData && organizationId) {
    const mainRepresentative = extractEntityRepresentativeName(elementData);
    const organizationData = await findOrganizationById(context, SYSTEM_USER, organizationId);
    const humanDescription = `Access requested:\n - by user: ${user.name} \n - for organization: ${organizationData.name} \n - for ${elementData.entity_type} ${mainRepresentative} ${elementData.id}`;

    const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.New);
    const rfiInput: CaseRfiAddInput = {
      name: `Request Access for entity ${mainRepresentative} by ${user.name} via organization ${organizationData.name}`,
      objectParticipant: [user.id],
      objects: requestedEntities,
      description: humanDescription,
      information_types: [REQUEST_SHARE_ACCESS_INFO_TYPE],
      x_opencti_request_access: `${JSON.stringify(action)}`,
      authorized_members,
      x_opencti_workflow_id
    };
    const requestForInformation = await addCaseRfi(context, SYSTEM_USER, rfiInput);
    return requestForInformation.id;
  }
  throw ValidationError('Missing parameters for Access Request', input);
};

export const approveRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkRequestAccessEnabled(context, user);
  const rfi = await findRFIById(context, user, id);
  if (rfi.x_opencti_request_access) {
    const actionData = rfi.x_opencti_request_access;
    const action: RequestAccessAction = JSON.parse(actionData);

    if (action.entities && action.members) {
      await addOrganizationRestriction(context, user, action.entities[0], action.members[0]);

      const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.Approved);
      const allActionStatuses = await getRFIStatusMap(context, user);
      // Moving RFI to approved
      const requestAccessAction: RequestAccessAction = {
        ...action,
        status: ActionStatus.Approved,
        executionDate: new Date(),
        workflowMapping: allActionStatuses
      };
      const RFIFieldPatch :EditInput[] = [
        { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
      ];

      if (x_opencti_workflow_id) {
        RFIFieldPatch.push({ key: 'x_opencti_workflow_id', value: [x_opencti_workflow_id] });
      }
      await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);

      return {
        action_executed: true,
        action_status: requestAccessAction.status,
        action_date: requestAccessAction.executionDate
      };
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
    return {
      action_executed: false,
      action_status: ActionStatus.MissingParameters,
    };
  }
  logApp.error('RFI not found for Request Access', { RFIId: id });
  return {
    action_executed: false,
    action_status: ActionStatus.NotFound,
  };
};

export const declineRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`Reject for RFI ${id}`);
  await checkRequestAccessEnabled(context, user);

  const rfi = await findRFIById(context, user, id);
  const actionData = rfi.x_opencti_request_access;
  const action: RequestAccessAction = JSON.parse(actionData);

  if (action.entities && action.members) {
    const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.Declined);
    const allActionStatuses = await getRFIStatusMap(context, user);
    const requestAccessAction: RequestAccessAction = {
      ...action,
      status: ActionStatus.Declined,
      executionDate: new Date(),
      workflowMapping: allActionStatuses
    };
    const RFIFieldPatch :EditInput[] = [
      { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] }
    ];

    if (x_opencti_workflow_id) {
      RFIFieldPatch.push({ key: 'x_opencti_workflow_id', value: [x_opencti_workflow_id] });
    }
    await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
    return {
      action_executed: true,
      action_status: ActionStatus.Declined,
      action_date: requestAccessAction.executionDate
    };
  }
  logApp.error('Request Access is missing entities or members', { action, RFIId: id });
  return {
    action_executed: false,
    action_status: ActionStatus.MissingParameters,
  };
};
