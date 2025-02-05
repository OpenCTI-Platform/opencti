import type { AuthContext, AuthUser } from '../../types/user';
import {
  type CaseRfiAddInput,
  type EditInput,
  FilterMode,
  OrderingMode,
  type RequestAccessAddInput,
  type RequestAccessConfigureInput,
  StatusOrdering
} from '../../generated/graphql';
import { addCaseRfi, findById as findRFIById } from '../case/case-rfi/case-rfi-domain';
import { SYSTEM_USER } from '../../utils/access';
import { listAllEntities } from '../../database/middleware-loader';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { isFeatureEnabled, logApp } from '../../config/conf';
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
import { ENTITY_TYPE_CONTAINER_CASE } from '../case/case-types';
import { findByType as findEntitySettingsByType, getRequestAccessStatus } from '../entitySetting/entitySetting-domain';

export const REQUEST_SHARE_ACCESS_INFO_TYPE = 'Request sharing';

export enum ActionStatus {
  APPROVED = 'APPROVED',
  DECLINED = 'DECLINED',
  NEW = 'NEW',
}

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

export const verifyRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  let message = '';
  if (!isFeatureEnabled('ORGA_SHARING_REQUEST_FF')) {
    return { enabled: false };
  }
  // 1. EE must be enabled
  const isEEConfigured: boolean = await isEnterpriseEdition(context);
  if (!isEEConfigured) {
    message += 'Enterprise edition must be enabled.';
  }
  // 2. Platform organization should be set up
  const platformOrgValue = await getPlatformOrganization(context, user);
  const isPlatformOrgSetup: boolean = platformOrgValue !== undefined && platformOrgValue !== '';
  if (!isPlatformOrgSetup) {
    message += 'Platform organization must be setup.';
  }
  // 3. Workflow should be enabled
  const rfiEntitySettings = await getRfiEntitySettings(context);
  const isWorkflowEnabled: boolean = rfiEntitySettings?.workflow_configuration !== undefined;
  if (!isWorkflowEnabled) {
    message += 'At least one workflow status must be configured.';
  }

  // 4. Request access status should be configured
  const areRequestAccessStatusConfigured: boolean = rfiEntitySettings?.request_access_workflow !== undefined
    && rfiEntitySettings.request_access_workflow.declined_workflow_id !== undefined
    && rfiEntitySettings.request_access_workflow.approved_workflow_id !== undefined;
  if (!areRequestAccessStatusConfigured) {
    message += 'RFI status for decline and approval must be configured in entity settings.';
  }

  // 5. Auth member admin should be configured.
  // FIXME uncomment when admin approval configuration is implemented
  const isRequestAccesApprovalAdminConfigured = true; // rfiEntitySettings?.request_access_workflow?.approval_admin !== undefined;
  if (!isRequestAccesApprovalAdminConfigured) {
    message += 'At least one approval administrator must be configured in entity settings.';
  }

  const isEnabled: boolean = isEEConfigured
    && isPlatformOrgSetup
    && isWorkflowEnabled
    && areRequestAccessStatusConfigured
    && isRequestAccesApprovalAdminConfigured;

  return {
    enabled: isEnabled,
    message
  };
};

export const isRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  const result = await verifyRequestAccessEnabled(context, user);
  return result.enabled;
};

export const checkRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  const result = await verifyRequestAccessEnabled(context, user);
  if (!result.enabled) {
    // TODO add doc code and doc page.
    throw FunctionalError('[OPENCTI-MODULE][Request access] Request access feature is missing configuration.', { message: result.message, doc_code: 'REQUEST_ACCESS_CONFIGURATION' });
  }
};

export const getRFIStatusForAction = async (context: AuthContext, user: AuthUser, action:ActionStatus) => {
  const rfiEntitySettings = await getRfiEntitySettings(context);
  const requestAccessWorkflow = rfiEntitySettings?.request_access_workflow;
  if (requestAccessWorkflow) {
    if (action === ActionStatus.APPROVED) {
      return requestAccessWorkflow.approved_workflow_id;
    }
    if (action === ActionStatus.DECLINED) {
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
      filters: [{ key: ['type'], values: [ENTITY_TYPE_CONTAINER_CASE] }],
      filterGroups: [],
      first: 1
    },
    connectionFormat: false
  };
  const allWorkflowStatus = await listAllEntities<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
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
        actionStatus: ActionStatus.APPROVED,
      });
    }

    if (requestAccessWorkflow.declined_workflow_id) {
      result.push({
        rfiStatusId: requestAccessWorkflow.declined_workflow_id,
        actionStatus: ActionStatus.DECLINED,
      });
    }
  }
  if (rfiEntitySettings?.workflow_configuration) {
    const firstStatus = await findFirstWorkflowStatus(context, user);
    result.push({
      rfiStatusId: firstStatus.internal_id,
      actionStatus: ActionStatus.NEW });
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
  throw FunctionalError('Please set an approval admin for request access');
};

export const configureRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessConfigureInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - configureRequestAccess', { input });
  await checkRequestAccessEnabled(context, user);

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);

  if (input.decline_status_template_id && rfiEntitySettings.request_access_workflow && rfiEntitySettings.request_access_workflow.declined_workflow_id) {
    const declineUpdateInput = [{ key: 'template_id', value: [input.decline_status_template_id] }];
    await updateAttribute(context, user, rfiEntitySettings.request_access_workflow.declined_workflow_id, ENTITY_TYPE_STATUS, declineUpdateInput);
  }

  if (input.approve_status_template_id && rfiEntitySettings.request_access_workflow && rfiEntitySettings.request_access_workflow.approved_workflow_id) {
    const approveUpdateInput = [{ key: 'template_id', value: [input.approve_status_template_id] }];
    await updateAttribute(context, user, rfiEntitySettings.request_access_workflow.approved_workflow_id, ENTITY_TYPE_STATUS, approveUpdateInput);
  }

  // TODO if (input.approval_admin)

  if (rfiEntitySettings) {
    const allStatus = await getRequestAccessStatus(context, user, rfiEntitySettings);
    return allStatus;
  }
  return null;
};

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - addRequestAccess', { input });
  await checkRequestAccessEnabled(context, user);
  // await initForDev(context);

  const requestedEntities = input.request_access_entities;
  const organizationId = input.request_access_members[0];
  const elementId = input.request_access_entities[0];

  const elementData = await elLoadById(context, SYSTEM_USER, elementId) as unknown as BasicStoreBase;
  if (elementData === undefined) {
    throw ValidationError('Element not found for Access Request', 'request_access_members', input);
  }

  const organizationData = await findOrganizationById(context, SYSTEM_USER, organizationId);
  if (organizationData === undefined) {
    throw ValidationError('Organization not found for Access Request', 'request_access_entities', input);
  }
  const authorized_members = await computeAuthorizedMembersForRequestAccess(context, user, input.request_access_entities);
  const mainRepresentative = extractEntityRepresentativeName(elementData);

  const humanDescription = 'Access requested:\n'
      + ` - by user: ${user.name} \n`
      + ` - for organization: ${organizationData.name} \n`
      + ` - for entity: ${elementData.entity_type} ${mainRepresentative} ${elementData.id}\n\n`
      + `Reason: ${input.request_access_reason}`;

  const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.NEW);

  const allActionStatuses = await getRFIStatusMap(context, user);
  const action: RequestAccessAction = {
    reason: input.request_access_reason || 'no reason',
    members: input.request_access_members,
    type: input.request_access_type?.toString(),
    entities: input.request_access_entities,
    status: ActionStatus.NEW,
    workflowMapping: allActionStatuses
  };

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
};

export const approveRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info('Approving request access:', { id });
  await checkRequestAccessEnabled(context, user);
  const rfi = await findRFIById(context, user, id);
  logApp.info('Approving request access, rfi:', { rfi });
  if (rfi.x_opencti_request_access) {
    const actionData = rfi.x_opencti_request_access;
    const action: RequestAccessAction = JSON.parse(actionData);

    if (action.entities && action.members) {
      await addOrganizationRestriction(context, user, action.entities[0], action.members[0]);

      const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.APPROVED);
      const allActionStatuses = await getRFIStatusMap(context, user);
      // Moving RFI to approved
      const requestAccessAction: RequestAccessAction = {
        ...action,
        status: ActionStatus.APPROVED,
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
      // TODO await publishUserAction(
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
  }
  logApp.error('RFI not found for Request Access', { RFIId: id });
  const rfiApproved = await findRFIById(context, user, id);
  logApp.info('rfiApproved:', { rfiApproved });
  return rfiApproved;
};

export const declineRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`Reject for RFI ${id}`);
  await checkRequestAccessEnabled(context, user);

  const rfi = await findRFIById(context, user, id);
  const actionData = rfi.x_opencti_request_access;
  const action: RequestAccessAction = JSON.parse(actionData);

  if (action.entities && action.members) {
    const x_opencti_workflow_id = await getRFIStatusForAction(context, user, ActionStatus.DECLINED);
    const allActionStatuses = await getRFIStatusMap(context, user);
    const requestAccessAction: RequestAccessAction = {
      ...action,
      status: ActionStatus.DECLINED,
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
    // TODO await publishUserAction(
  }
  logApp.error('Request Access is missing entities or members', { action, RFIId: id });

  const rfiDeclined = await findRFIById(context, user, id);
  logApp.info('rfiDeclined:', { rfiDeclined });
  return rfiDeclined;
};
