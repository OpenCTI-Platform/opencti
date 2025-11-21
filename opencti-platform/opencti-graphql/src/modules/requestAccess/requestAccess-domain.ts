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
  StatusScope,
  VocabularyCategory
} from '../../generated/graphql';
import { addCaseRfi, findById as findRFIById } from '../case/case-rfi/case-rfi-domain';
import {
  getUserAccessRight,
  isUserCanAccessStoreElement,
  isUserHasCapability,
  KNOWLEDGE_ORGANIZATION_RESTRICT,
  MEMBER_ACCESS_RIGHT_ADMIN,
  MEMBER_ACCESS_RIGHT_EDIT,
  SYSTEM_USER
} from '../../utils/access';
import { internalLoadById, fullEntitiesList } from '../../database/middleware-loader';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_STATUS } from '../../schema/internalObject';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { addOrganizationRestriction } from '../../domain/stix';
import { storeLoadByIdWithRefs, updateAttribute } from '../../database/middleware';
import { ABSTRACT_STIX_DOMAIN_OBJECT, OPENCTI_ADMIN_UUID } from '../../schema/general';
import { findById as findOrganizationById } from '../organization/organization-domain';
import { elLoadById } from '../../database/engine';
import type { BasicGroupEntity, BasicStoreBase, BasicStoreCommon, BasicStoreEntity, BasicWorkflowStatus } from '../../types/store';
import { extractEntityRepresentativeName } from '../../database/entity-representative';
import { type BasicStoreEntityCaseRfi, ENTITY_TYPE_CONTAINER_CASE_RFI } from '../case/case-rfi/case-rfi-types';
import { FunctionalError, UnsupportedError, ValidationError } from '../../config/errors';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import type { BasicStoreSettings } from '../../types/settings';
import { entitySettingEditField, findByType as findEntitySettingsByType } from '../entitySetting/entitySetting-domain';
import { findById as findStatusById } from '../../domain/status';
import { type BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';
import { findById as findGroupById } from '../../domain/group';
import { getDraftContext } from '../../utils/draftContext';
import { notify, storeNotificationEvent } from '../../database/redis';
import { publishUserAction } from '../../listener/UserActionListener';
import { verifyRequestAccessEnabled } from './requestAccessUtils';
import { isEmptyField, isNotEmptyField } from '../../database/utils';
import { RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { addVocabulary } from '../vocabulary/vocabulary-domain';
import {
  type ActionNotificationEvent,
  EVENT_NOTIFICATION_VERSION,
  type NotificationUser,
  platformNotification,
  REQUEST_SHARE_ACCESS_INFO_TYPE
} from '../../manager/notificationManager';
import { addRequestAccessCreationCount } from '../../manager/telemetryManager';

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
  type?: string
  status: string
  applicant_id: string
  executionDate?: Date
  workflowMapping: RequestAccessActionStatus[],
}

export const getPlatformOrganizationId = async (context: AuthContext, user: AuthUser) => {
  const settings: BasicStoreSettings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS);
  return settings.platform_organization;
};

export const getRfiEntitySettings = async (context: AuthContext, user: AuthUser) => {
  return findEntitySettingsByType(context, user, ENTITY_TYPE_CONTAINER_CASE_RFI);
};

// shortcut for entitySettings resolver
export const isRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS) as BasicStoreSettings;
  const rfiEntitySettings = await getRfiEntitySettings(context, user);
  const result = verifyRequestAccessEnabled(settings, rfiEntitySettings);
  return result.enabled === true;
};

const checkRequestAccessEnabled = async (context: AuthContext, user: AuthUser) => {
  const draftContext = getDraftContext(context, user);
  if (draftContext) {
    // If request access get allowed in draft, remove also condition in middleware near isRequestAccessConfigured
    throw ValidationError('Request access is not available in draft mode');
  }
  const settings = await getEntityFromCache(context, user, ENTITY_TYPE_SETTINGS) as BasicStoreSettings;
  const rfiEntitySettings = await getRfiEntitySettings(context, user);
  const result = verifyRequestAccessEnabled(settings, rfiEntitySettings);
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
    }
  };
  const allRequestAccessStatus = await fullEntitiesList<BasicWorkflowStatus>(context, user, [ENTITY_TYPE_STATUS], args);
  logApp.debug('[OPENCTI-MODULE][Request access] Found first status as:', { status: allRequestAccessStatus[0] });
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

export const computeAuthorizedMembersForRequestAccess = async (context: AuthContext, user: AuthUser, element: BasicStoreCommon) => {
  const authorizedMembers = [];
  const rfiEntitySettings = await getRfiEntitySettings(context, user);

  if (element.restricted_members) {
    throw FunctionalError('This entity is restricted with authorized member and cannot be requested for sharing.', { id: element.id });
  }

  if (!rfiEntitySettings.request_access_workflow?.approval_admin || rfiEntitySettings.request_access_workflow?.approval_admin.length === 0) {
    throw FunctionalError('Request access cannot be created because no approval admin is configured.');
  }

  const approvalAdmins: string[] = rfiEntitySettings.request_access_workflow?.approval_admin;

  authorizedMembers.push({
    id: OPENCTI_ADMIN_UUID,
    access_right: MEMBER_ACCESS_RIGHT_ADMIN,
  });

  let organizationIdsToUse: string[];
  if (element.granted && element.granted.length > 0) {
    organizationIdsToUse = element.granted;
  } else {
    // on knowledge without organization restriction, fallback to platform org.
    const platformOrganizationId = await getPlatformOrganizationId(context, user);
    organizationIdsToUse = [platformOrganizationId];
  }

  // Build auth member intersection will all organizations
  for (let orgI = 0; orgI < organizationIdsToUse.length; orgI += 1) {
    for (let adminI = 0; adminI < approvalAdmins.length; adminI += 1) {
      authorizedMembers.push({
        id: organizationIdsToUse[orgI],
        access_right: MEMBER_ACCESS_RIGHT_EDIT,
        groups_restriction_ids: [approvalAdmins[adminI]]
      });
    }
  }
  return authorizedMembers;
};

export const isUserCanActionRequestAccess = async (context: AuthContext, user: AuthUser, rfi: BasicStoreEntityCaseRfi) => {
  if (getDraftContext(context, user)) {
    // Accept and Decline button on RFI should be hidden in draft context.
    return false;
  }

  // User need to have edit capability on the RFI
  const userAccessRight = getUserAccessRight(user, rfi);
  const isRfiRestricted = userAccessRight === MEMBER_ACCESS_RIGHT_ADMIN || userAccessRight === MEMBER_ACCESS_RIGHT_EDIT;
  const isRfiAccessible = await isUserCanAccessStoreElement(context, user, rfi);
  const isCanEdit = isRfiAccessible && isRfiRestricted;
  // User need to have sharing capability to start the action
  const isCanManageSharing = isUserHasCapability(user, KNOWLEDGE_ORGANIZATION_RESTRICT); // Imply KNUPDATE
  return isCanEdit && isCanManageSharing;
};

export const getRequestAccessConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting
) => {
  logApp.debug('[OPENCTI-MODULE][Request Access] getRequestAccessConfiguration - entitySetting:', { entitySettings: entitySetting });
  let declinedStatus;
  let approvedStatus;
  const allAdmins = [];
  logApp.debug('[OPENCTI-MODULE][Request Access] entitySetting ok', {
    approvedId: entitySetting.request_access_workflow?.approved_workflow_id,
    declinedId: entitySetting.request_access_workflow?.declined_workflow_id,
    approval_admin: entitySetting.request_access_workflow?.approval_admin,
  });
  const declinedId = entitySetting.request_access_workflow?.declined_workflow_id;
  if (declinedId) {
    logApp.debug('[OPENCTI-MODULE][Request Access] findStatusById:', { statusId: declinedId });
    declinedStatus = await findStatusById(context, user, declinedId);
  }
  if (entitySetting.request_access_workflow?.approved_workflow_id) {
    logApp.debug('[OPENCTI-MODULE][Request Access] findStatusById:', { statusId: entitySetting.request_access_workflow?.approved_workflow_id });
    approvedStatus = await findStatusById(context, user, entitySetting.request_access_workflow?.approved_workflow_id);
  }
  if (entitySetting.request_access_workflow?.approval_admin) {
    logApp.debug('[OPENCTI-MODULE][Request Access] approval_admin before looking for members:', { approval_admin: entitySetting.request_access_workflow?.approval_admin });

    const approvalAdminIds = entitySetting.request_access_workflow?.approval_admin;

    if (approvalAdminIds.length > 0) {
      for (let i = 0; i < approvalAdminIds.length; i += 1) {
        const group: BasicGroupEntity = await findGroupById(context, user, approvalAdminIds[0]) as unknown as BasicGroupEntity;
        logApp.debug('[OPENCTI-MODULE][Request Access] approval_admin members:', { group });
        // group previously selected can be deleted at some point.
        if (group) {
          allAdmins.push({
            id: group.id,
            name: group.name
          });
        }
      }
    }
  }
  const requestAccessConfigResult: RequestAccessConfiguration = {
    declined_status: declinedStatus,
    approved_status: approvedStatus,
    approval_admin: allAdmins,
    id: REQUEST_ACCESS_CONFIGURATION_ID,
  };
  logApp.debug('[OPENCTI-MODULE][Request Access] getRequestAccessConfiguration result:', requestAccessConfigResult);
  return requestAccessConfigResult;
};

export const getRfiAccessConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  rfi: BasicStoreEntityCaseRfi
) => {
  const rfiEntitySettings = await getRfiEntitySettings(context, user);
  const requestAccessConfiguration = await getRequestAccessConfiguration(context, user, rfiEntitySettings);
  const isUserCanAction = await isUserCanActionRequestAccess(context, user, rfi);
  return {
    configuration: requestAccessConfiguration,
    isUserCanAction
  };
};

export const configureRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessConfigureInput) => {
  logApp.debug('[OPENCTI-MODULE][Request access] - configureRequestAccess', { input });

  const rfiEntitySettings = await findEntitySettingsByType(context, SYSTEM_USER, ENTITY_TYPE_CONTAINER_CASE_RFI);

  let approved_workflow_id;
  let declined_workflow_id;
  if (rfiEntitySettings.request_access_workflow) {
    approved_workflow_id = rfiEntitySettings.request_access_workflow.approved_workflow_id;
    declined_workflow_id = rfiEntitySettings.request_access_workflow.declined_workflow_id;
  }

  let approvedStatusData;
  if (input.approved_status_id) {
    approvedStatusData = await findWorkflowStatusByTemplateId(context, user, input.approved_status_id);
    logApp.debug('[OPENCTI-MODULE][Request access] - found approve status', { statusId: input.approved_status_id, approvedStatusData });
    if (approvedStatusData) {
      approved_workflow_id = approvedStatusData?.id;
    }
  }

  let declinedStatusData;
  if (input.declined_status_id) {
    declinedStatusData = await findWorkflowStatusByTemplateId(context, user, input.declined_status_id);
    logApp.debug('[OPENCTI-MODULE][Request access] - found declined status', { statusId: input.declined_status_id, declinedStatusData });
    if (declinedStatusData) {
      declined_workflow_id = declinedStatusData?.id;
    }
  }

  let approval_admin: string [] = [];
  if (input.approval_admin) {
    approval_admin = input.approval_admin as string [];
  }
  const newConfiguration = {
    approval_admin,
    approved_workflow_id,
    declined_workflow_id,
  };
  const editInput: EditInput[] = [
    { key: 'request_access_workflow', value: [newConfiguration] }
  ];
  const updated = await entitySettingEditField(context, user, rfiEntitySettings.id, editInput);
  logApp.debug('[OPENCTI-MODULE][Request access] - Update result', { updated });

  const approvalAdminsMembers: RequestAccessMember[] = [];
  if (approval_admin.length > 0) {
    for (let i = 0; i < approval_admin.length; i += 1) {
      const approvalAdminId = approval_admin[i];
      if (approvalAdminId) {
        const groupData: BasicGroupEntity = await findGroupById(context, user, approvalAdminId) as unknown as BasicGroupEntity;
        if (groupData) {
          approvalAdminsMembers.push({
            id: groupData.id,
            name: groupData.name,
          });
        }
      }
    }
  }
  const requestAccessConfigResult: RequestAccessConfiguration = {
    declined_status: declinedStatusData,
    approved_status: approvedStatusData,
    approval_admin: approvalAdminsMembers,
    id: REQUEST_ACCESS_CONFIGURATION_ID
  };
  logApp.debug('[OPENCTI-MODULE][Request access] - requestAccessConfigResult', { requestAccessConfigResult });
  return requestAccessConfigResult;
};

export const addRequestAccess = async (context: AuthContext, user: AuthUser, input: RequestAccessAddInput) => {
  logApp.debug('[OPENCTI-MODULE][Request access] - addRequestAccess', { input });
  await checkRequestAccessEnabled(context, user);

  const requestedEntities = input.request_access_entities;
  const organizationId = input.request_access_members[0];
  const elementId = input.request_access_entities[0];

  // region check validity
  const elementData = await storeLoadByIdWithRefs(context, SYSTEM_USER, elementId) as unknown as BasicStoreCommon;
  logApp.debug('[OPENCTI-MODULE][Request access] entity to request access on:', { elementData });
  if (elementData === undefined) {
    throw ValidationError('Element not found for Access Request', 'request_access_members', input);
  }
  const organizationData = await findOrganizationById(context, SYSTEM_USER, organizationId);
  if (organizationData === undefined) {
    throw ValidationError('Organization not found for Access Request', 'request_access_entities', input);
  }
  // endregion
  // Ensure the required vocab is available
  const category = VocabularyCategory.RequestForInformationTypesOv;
  await addVocabulary(context, SYSTEM_USER, { name: REQUEST_SHARE_ACCESS_INFO_TYPE, description: 'Request for information sharing process', category });
  // Create the new RFI
  const authorized_members = await computeAuthorizedMembersForRequestAccess(context, user, elementData);
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
    workflowMapping: allActionStatuses,
    applicant_id: user.id
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
    objectMarking: elementData[RELATION_OBJECT_MARKING] ?? [],
    x_opencti_workflow_id: firstStatus.id,
    revoked: false
  };
  const requestForInformation = await addCaseRfi(context, SYSTEM_USER, rfiInput);
  await addRequestAccessCreationCount();
  logApp.debug(`[OPENCTI-MODULE][Request access] - RFI created with id=${requestForInformation.id}`);
  return requestForInformation.id;
};

export const checkRequestActionAndGetWorkflow = async (context: AuthContext, user: AuthUser, id: string, status: ActionStatus) => {
  // region Check validity
  await checkRequestAccessEnabled(context, user);
  const rfi = await findRFIById(context, user, id);
  if (!rfi.x_opencti_request_access) {
    throw UnsupportedError('This RFI is not compatible', { id });
  }
  const actionData = rfi.x_opencti_request_access;
  const action: RequestAccessAction = JSON.parse(actionData);
  if (!action.entities || !action.members) {
    throw UnsupportedError('This RFI is not compatible', { id });
  }
  const x_opencti_workflow_id = await getRFIStatusForAction(context, user, status);
  if (isEmptyField((x_opencti_workflow_id))) {
    throw UnsupportedError('This RFI is not correctly configured', { id });
  }
  // endregion
  return { action, x_opencti_workflow_id };
};

export const notifyRequestAccessResult = async (
  context: AuthContext,
  user: AuthUser,
  instanceToShare: BasicStoreEntity,
  applicantId: string,
  representative: string,
  status: ActionStatus
) => {
  const applicant = await internalLoadById<any>(context, SYSTEM_USER, applicantId);
  const targets: Array<{ user: NotificationUser, type: string, message: string }> = [{
    user: {
      user_id: applicant.id,
      user_email: applicant.user_email,
      notifiers: applicant.personal_notifiers,
      user_service_account: user.user_service_account ? user.user_service_account : false
    },
    type: 'ACCESS REQUEST',
    message: `${representative} request access is now ${status}`
  }];
  const notificationEvent: ActionNotificationEvent = {
    version: EVENT_NOTIFICATION_VERSION,
    notification_id: platformNotification(applicant),
    type: 'action',
    targets,
    data: {
      id: status === ActionStatus.APPROVED ? instanceToShare.standard_id : null,
      representative: {
        main: `Access request ${status}`,
        secondary: '-',
      }
    },
    origin: {
      user_id: user.id, // User responsible for the action
    }
  };
  await storeNotificationEvent(context, notificationEvent);
};

export const approveRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkRequestAccessEnabled(context, user);
  logApp.debug('[OPENCTI-MODULE][Request Access] Approving request access:', { id });
  const entityCaseRfi = await internalLoadById<BasicStoreEntityCaseRfi>(context, user, id);
  const isUserCanAction = await isUserCanActionRequestAccess(context, user, entityCaseRfi);
  if (!isUserCanAction) {
    throw UnsupportedError('You need to be able to edit the RFI and share knowledge', { id });
  }
  // region Check validity
  const { action, x_opencti_workflow_id } = await checkRequestActionAndGetWorkflow(context, user, id, ActionStatus.APPROVED);
  // endregion
  // region Check if the target instance can be manipulated
  const targetInstanceToShare = (action.entities ?? [])[0];
  const instanceToShare = await internalLoadById<BasicStoreEntity>(context, user, targetInstanceToShare);
  if (isEmptyField(instanceToShare)) {
    throw UnsupportedError('You cant share the requested element (restrictions or markings)', { targetInstanceToShare });
  }
  // If user have access but restrictions is applied, element will not be shared by organization
  if (isNotEmptyField((instanceToShare.restricted_members))) {
    throw UnsupportedError('Element is not sharable at the moment (restricted)', { targetInstanceToShare });
  }
  // endregion
  // region Execute the sharing
  await addOrganizationRestriction(context, user, targetInstanceToShare, (action.members ?? [])[0]);
  // endregion
  // region Moving RFI to approved
  const allActionStatuses = await getRFIStatusMap(context, user);
  const requestAccessAction: RequestAccessAction = {
    ...action,
    status: ActionStatus.APPROVED,
    executionDate: new Date(),
    workflowMapping: allActionStatuses
  };
  const RFIFieldPatch :EditInput[] = [
    { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
    { key: 'x_opencti_workflow_id', value: [x_opencti_workflow_id] }
  ];
  const { element } = await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
  const elementData = await elLoadById(context, SYSTEM_USER, targetInstanceToShare) as unknown as BasicStoreBase;
  const mainRepresentative = extractEntityRepresentativeName(elementData);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `approved demand of request access for entity ${mainRepresentative}`,
    context_data: { id: user.id, entity_type: ENTITY_TYPE_CONTAINER_CASE_RFI, input: requestAccessAction }
  });
  // endregion
  // Notify the user
  await notifyRequestAccessResult(context, user, instanceToShare, action.applicant_id, mainRepresentative, ActionStatus.APPROVED);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
};

export const declineRequestAccess = async (context: AuthContext, user: AuthUser, id: string) => {
  await checkRequestAccessEnabled(context, user);
  logApp.debug(`[OPENCTI-MODULE][Request Access] Reject for RFI ${id}`);
  // region Check validity
  const { action, x_opencti_workflow_id } = await checkRequestActionAndGetWorkflow(context, user, id, ActionStatus.DECLINED);
  // endregion
  // region Moving RFI to rejected
  const allActionStatuses = await getRFIStatusMap(context, user);
  const requestAccessAction: RequestAccessAction = {
    ...action,
    status: ActionStatus.DECLINED,
    executionDate: new Date(),
    workflowMapping: allActionStatuses
  };
  const RFIFieldPatch :EditInput[] = [
    { key: 'x_opencti_request_access', value: [`${JSON.stringify(requestAccessAction)}`] },
    { key: 'x_opencti_workflow_id', value: [x_opencti_workflow_id] }
  ];
  const { element } = await updateAttribute(context, user, id, ABSTRACT_STIX_DOMAIN_OBJECT, RFIFieldPatch);
  const instanceToShare = await internalLoadById<BasicStoreEntity>(context, SYSTEM_USER, (action.entities ?? [])[0]);
  const mainRepresentative = extractEntityRepresentativeName(instanceToShare);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `declined demand of request access for entity ${mainRepresentative}`,
    context_data: { id: user.id, entity_type: ENTITY_TYPE_CONTAINER_CASE_RFI, input: requestAccessAction }
  });
  // endregion
  // Notify the user
  await notifyRequestAccessResult(context, user, instanceToShare, action.applicant_id, mainRepresentative, ActionStatus.DECLINED);
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].EDIT_TOPIC, element, user);
};
