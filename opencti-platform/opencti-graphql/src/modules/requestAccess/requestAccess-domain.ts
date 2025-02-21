import type { AuthContext, AuthUser } from '../../types/user';
import {
  type CaseRfiAddInput,
  type EditInput,
  FilterMode,
  OrderingMode,
  type RequestAccessAddInput,
  type RequestAccessConfiguration,
  type RequestAccessConfigureInput,
  type RequestAccessMember,
  StatusOrdering,
  StatusScope
} from '../../generated/graphql';
import { addCaseRfi, findById as findRFIById } from '../case/case-rfi/case-rfi-domain';
import { SYSTEM_USER } from '../../utils/access';
import { listAllEntities } from '../../database/middleware-loader';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { isFeatureEnabled, logApp } from '../../config/conf';
import { addOrganizationRestriction } from '../../domain/stix';
import { updateAttribute } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { findById as findOrganizationById } from '../organization/organization-domain';
import { elLoadById } from '../../database/engine';
import type { BasicGroupEntity, BasicStoreBase, BasicWorkflowStatus } from '../../types/store';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { FunctionalError, ValidationError } from '../../config/errors';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';
import type { BasicStoreSettings } from '../../types/settings';
import { entitySettingEditField, findByType as findEntitySettingsByType } from '../entitySetting/entitySetting-domain';
import { findById as findStatusById } from '../../domain/status';
import { type BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';
import { findById as findGroupById } from '../../domain/group';

export const REQUEST_SHARE_ACCESS_INFO_TYPE = 'Request sharing';

// having an id is required for Relay
const REQUEST_ACCESS_CONFIGURATION_ID = '7059b2f9-86d4-419b-9fde-adf825090820';

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
  const settings: BasicStoreSettings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
  return settings.platform_organization;
};

export const getRfiEntitySettings = async (context: AuthContext, user: AuthUser) => {
  return findEntitySettingsByType(context, user, ENTITY_TYPE_CONTAINER_CASE_RFI);
  // return getEntitySettingFromCache(context, ENTITY_TYPE_CONTAINER_CASE_RFI);
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
  const rfiEntitySettings = await getRfiEntitySettings(context, user);

  // 3. Request access status should be configured
  const areRequestAccessStatusConfigured: boolean = rfiEntitySettings?.request_access_workflow !== undefined
    && rfiEntitySettings.request_access_workflow.declined_workflow_id !== undefined
    && rfiEntitySettings.request_access_workflow.approved_workflow_id !== undefined;
  if (!areRequestAccessStatusConfigured) {
    message += 'RFI status for decline and approval must be configured in entity settings.';
  }

  // 4. At least one auth member admin should be configured.
  const isRequestAccesApprovalAdminConfigured: boolean = rfiEntitySettings?.request_access_workflow?.approval_admin !== undefined
    && rfiEntitySettings?.request_access_workflow?.approval_admin.length >= 1;
  if (!isRequestAccesApprovalAdminConfigured) {
    message += 'At least one approval administrator must be configured in entity settings.';
  }

  const isEnabled: boolean = isEEConfigured
    && isPlatformOrgSetup
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
    throw FunctionalError(`Request access feature is missing configuration: ${result.message}`, { message: result.message, doc_code: 'REQUEST_ACCESS_CONFIGURATION' });
  }
};

export const getRFIStatusForAction = async (context: AuthContext, user: AuthUser, action:ActionStatus) => {
  const rfiEntitySettings = await getRfiEntitySettings(context, user);
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

export const findWorkflowStatusByTemplateId = async (context: AuthContext, user: AuthUser, templateId: string) => {
  const platformStatuses = await getEntitiesListFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
  const allStatusesByScope = platformStatuses.filter((status) => status.scope === StatusScope.RequestAccess && status.template_id === templateId);
  logApp.info('ANGIE findWorkflowStatusByTemplateId, found', { templateId, status: allStatusesByScope[0] });
  return allStatusesByScope[0];
};

export const findFirstWorkflowStatus = async (context: AuthContext, user: AuthUser) => {
  const args = {
    orderBy: StatusOrdering.Order,
    orderMode: OrderingMode.Asc,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['type'], values: [ENTITY_TYPE_CONTAINER_CASE_RFI] },
        { key: ['scope'], values: [StatusScope.RequestAccess] }
      ],
      filterGroups: [],
    },
    connectionFormat: false
  };
  const allRequestAccessStatus = await listAllEntities<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
  logApp.info('[OPENCTI-MODULE][Request access] Found first status as:', { status: allRequestAccessStatus[0] });
  return allRequestAccessStatus[0];
};

export const getRFIStatusMap = async (context: AuthContext, user: AuthUser) => {
  const rfiEntitySettings = await getRfiEntitySettings(context, user);
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

const computeAuthorizedMembersForRequestAccess = async (context: AuthContext, user: AuthUser) => {
  const authorizedMembers = [];
  const rfiEntitySettings = await getRfiEntitySettings(context, user);

  if (rfiEntitySettings && rfiEntitySettings.request_access_workflow) {
    const requestAccessAdmins = rfiEntitySettings.request_access_workflow.approval_admin;
    if (requestAccessAdmins.length > 0) {
      for (let i = 0; i < requestAccessAdmins.length; i += 1) {
        authorizedMembers.push({
          id: requestAccessAdmins[i],
          access_right: 'admin',
        });
      }
      return authorizedMembers;
    }
  }
  throw FunctionalError('Please set an approval admin for request access in Request For Information configuration.');
};

export const getRequestAccessConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting | undefined
) => {
  let rfiEntitySettings = entitySetting;
  if (entitySetting) {
    rfiEntitySettings = await getRfiEntitySettings(context, user);
  }
  logApp.info('[OPENCTI-MODULE][Request Access] getRequestAccessConfiguration - entitySetting:', { rfiEntitySettings });
  let declinedStatus;
  let approvedStatus;
  let approvalAdmin;
  if (rfiEntitySettings) {
    logApp.info('[OPENCTI-MODULE][Request Access] rfiEntitySettings ok', {
      approvedId: rfiEntitySettings.request_access_workflow?.approved_workflow_id,
      declinedId: rfiEntitySettings.request_access_workflow?.declined_workflow_id,
      approval_admin: rfiEntitySettings.request_access_workflow?.approval_admin,
    });

    const declinedId = rfiEntitySettings.request_access_workflow?.declined_workflow_id;
    if (declinedId) {
      logApp.info('[OPENCTI-MODULE][Request Access] findStatusById:', { statusId: declinedId });
      declinedStatus = await findStatusById(context, user, declinedId);
    }

    if (rfiEntitySettings.request_access_workflow?.approved_workflow_id) {
      logApp.info('[OPENCTI-MODULE][Request Access] findStatusById:', { statusId: rfiEntitySettings.request_access_workflow?.approved_workflow_id });
      approvedStatus = await findStatusById(context, user, rfiEntitySettings.request_access_workflow?.approved_workflow_id);
    }

    if (rfiEntitySettings.request_access_workflow?.approval_admin) {
      logApp.info('[OPENCTI-MODULE][Request Access] approval_admin before looking for members:', { approval_admin: rfiEntitySettings.request_access_workflow?.approval_admin });

      const approvalAdminIds = rfiEntitySettings.request_access_workflow?.approval_admin;

      if (approvalAdminIds.length > 0) {
        const group: BasicGroupEntity = await findGroupById(context, user, approvalAdminIds[0]) as unknown as BasicGroupEntity;
        logApp.info('[OPENCTI-MODULE][Request Access] approval_admin members:', { group });
        approvalAdmin = {
          id: group.id,
          name: group.name
        };
      }
    }

    const requestAccessConfigResult: RequestAccessConfiguration = {
      declined_status: declinedStatus,
      approved_status: approvedStatus,
      approval_admin: [approvalAdmin],
      id: REQUEST_ACCESS_CONFIGURATION_ID,
    };
    logApp.info('[OPENCTI-MODULE][Request Access] getRequestAccessConfiguration result:', requestAccessConfigResult);
    return requestAccessConfigResult;
  }
  return null;
};

export const configureRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessConfigureInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - configureRequestAccess', { input });

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);

  const { approval_admin } = input;
  let approved_workflow_id;
  let declined_workflow_id;
  if (rfiEntitySettings.request_access_workflow) {
    approved_workflow_id = rfiEntitySettings.request_access_workflow.approved_workflow_id;
    declined_workflow_id = rfiEntitySettings.request_access_workflow.declined_workflow_id;
  }

  let approvedStatusData;
  if (input.approved_status_id) {
    approvedStatusData = await findWorkflowStatusByTemplateId(context, user, input.approved_status_id);
    logApp.info('[OPENCTI-MODULE][Request access] - found approve status', { statusId: input.approved_status_id, approvedStatusData });
    if (approvedStatusData) {
      approved_workflow_id = approvedStatusData?.id;
    }
  }

  let declinedStatusData;
  if (input.declined_status_id) {
    declinedStatusData = await findWorkflowStatusByTemplateId(context, user, input.declined_status_id);
    logApp.info('[OPENCTI-MODULE][Request access] - found declined status', { statusId: input.declined_status_id, declinedStatusData });
    if (declinedStatusData) {
      declined_workflow_id = declinedStatusData?.id;
    }
  }

  const newConfiguration = {
    approval_admin,
    approved_workflow_id,
    declined_workflow_id,
  };
  const editInput: EditInput[] = [
    { key: 'request_access_workflow', value: [newConfiguration] }
  ];
  logApp.info('[OPENCTI-MODULE][Request access] - Update with', { editInput });
  const updated = await entitySettingEditField(context, user, rfiEntitySettings.id, editInput);
  logApp.info('[OPENCTI-MODULE][Request access] - Update result', { updated });

  const groupData: BasicGroupEntity = await findGroupById(context, user, approval_admin) as unknown as BasicGroupEntity;

  const approvalAdmin: RequestAccessMember = {
    id: groupData.id,
    name: groupData.name,
  };

  const requestAccessConfigResult: RequestAccessConfiguration = {
    declined_status: declinedStatusData,
    approved_status: approvedStatusData,
    approval_admin: [approvalAdmin],
    id: REQUEST_ACCESS_CONFIGURATION_ID
  };
  return requestAccessConfigResult;
};

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  logApp.info('[OPENCTI-MODULE][Request access] - addRequestAccess', { input });
  await checkRequestAccessEnabled(context, user);

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
  const authorized_members = await computeAuthorizedMembersForRequestAccess(context, user);
  const mainRepresentative = extractEntityRepresentativeName(elementData);

  const humanDescription = 'Access requested:\n'
      + ` - by user: ${user.name} \n`
      + ` - for organization: ${organizationData.name} \n`
      + ` - for entity: ${elementData.entity_type} ${mainRepresentative} ${elementData.id}\n\n`
      + `Reason: ${input.request_access_reason}`;

  const allActionStatuses = await getRFIStatusMap(context, user);
  const action: RequestAccessAction = {
    reason: input.request_access_reason || 'no reason',
    members: input.request_access_members,
    type: input.request_access_type?.toString(),
    entities: input.request_access_entities,
    status: ActionStatus.NEW,
    workflowMapping: allActionStatuses
  };

  const firstStatus: BasicWorkflowStatus = await findFirstWorkflowStatus(context, user);
  const rfiInput: CaseRfiAddInput = {
    name: `Request Access for entity ${mainRepresentative} by ${user.name} via organization ${organizationData.name}`,
    objectParticipant: [user.id],
    objects: requestedEntities,
    description: humanDescription,
    information_types: [REQUEST_SHARE_ACCESS_INFO_TYPE],
    x_opencti_request_access: `${JSON.stringify(action)}`,
    authorized_members,
    x_opencti_workflow_id: firstStatus.id,
  };
  const requestForInformation = await addCaseRfi(context, SYSTEM_USER, rfiInput);
  logApp.info(`[OPENCTI-MODULE][Request access] - RFI created with id=${requestForInformation.id}`);
  return requestForInformation.id;
};

export const approveRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info('[OPENCTI-MODULE][Request Access] Approving request access:', { id });
  await checkRequestAccessEnabled(context, user);
  const rfi = await findRFIById(context, user, id);
  logApp.info('[OPENCTI-MODULE][Request Access] Approving request access, rfi:', { rfi });
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
      // TODO in chunk 2 => await publishUserAction(
    }
    logApp.error('Request Access is missing entities or members', { action, RFIId: id });
  }
  logApp.error('RFI not found for Request Access', { RFIId: id });
  const rfiApproved = await findRFIById(context, user, id);
  logApp.info('[OPENCTI-MODULE][Request Access] rfiApproved:', { rfiApproved });
  return rfiApproved;
};

export const declineRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  logApp.info(`[OPENCTI-MODULE][Request Access] Reject for RFI ${id}`);
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
    // TODO in chunk 2 => await publishUserAction(
  }
  logApp.error('[OPENCTI-MODULE][Request Access] Missing entities or members', { action, RFIId: id });

  const rfiDeclined = await findRFIById(context, user, id);
  logApp.info('[OPENCTI-MODULE][Request Access] rfiDeclined:', { rfiDeclined });
  return rfiDeclined;
};
