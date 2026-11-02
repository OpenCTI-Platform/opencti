import type { ImportContext } from './context';
import type { StixObject } from './types';
import { first, getAttributeInExtension, isMissing, iterate, pythonTruthy, required } from './utils';

// Calls the operations make on the internal objects (pycti/entities: opencti_user.py,
// opencti_group.py, opencti_role.py; pycti/api: opencti_api_work.py, opencti_api_trash.py,
// opencti_api_draft.py, opencti_api_playbook.py, opencti_api_workspace.py,
// opencti_api_public_dashboard.py, opencti_api_notification.py, opencti_api_internal_file.py,
// opencti_api_pir.py). pycti info logs are not ported. pycti sends some errors to its
// admin_logger, not to its app_logger: they go to the warn channel here, so that only the
// app_logger errors are reported as errors.

// region user
const USER_FIELD_PATCH = `
  mutation UserEdit($id: ID!, $input: [EditInput]!) {
    userEdit(id: $id) { fieldPatch(input: $input) { id } }
  }
`;
const USER_DELETE = `
  mutation DeleteUser($id: ID!) {
    userEdit(id: $id) { delete }
  }
`;
const USER_ADD_MEMBERSHIP = `
  mutation UserEditAddMembership($id: ID!, $group_id: ID!) {
    userEdit(id: $id) { relationAdd(input: { relationship_type: "member-of", toId: $group_id }) { id } }
  }
`;
const USER_DELETE_MEMBERSHIP = `
  mutation UserEditDeleteMembership($id: ID!, $group_id: StixRef!) {
    userEdit(id: $id) { relationDelete(toId: $group_id, relationship_type: "member-of") { id } }
  }
`;
const USER_ADD_ORGANIZATION = `
  mutation UserEditAddOrganization($id: ID!, $organization_id: ID!) {
    userEdit(id: $id) { organizationAdd(organizationId: $organization_id) { id } }
  }
`;
const USER_DELETE_ORGANIZATION = `
  mutation UserEditDeleteOrganization($id: ID!, $organization_id: ID!) {
    userEdit(id: $id) { organizationDelete(organizationId: $organization_id) { id } }
  }
`;
const SEND_USER_MAIL = `
  mutation SendUserMail($input: SendUserMailInput!) {
    sendUserMail(input: $input)
  }
`;

// pycti user.update_field
export const updateUserField = async (context: ImportContext, id: string | null, input: unknown) => {
  if (isMissing(id) || isMissing(input)) {
    context.logger.warn('[opencti_user] Missing parameters: id and input');
    return;
  }
  await context.client.query(USER_FIELD_PATCH, { id, input });
};

// pycti user.delete
const deleteUser = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.warn('[opencti_user] Missing parameter: id');
    return;
  }
  await context.client.query(USER_DELETE, { id });
};

// pycti user.add_membership
export const addUserMembership = async (context: ImportContext, id: string | null, groupId: unknown) => {
  if (isMissing(id) || isMissing(groupId)) {
    context.logger.warn('[opencti_user] Missing parameters: id and group_id');
    return;
  }
  await context.client.query(USER_ADD_MEMBERSHIP, { id, group_id: groupId });
};

// pycti user.delete_membership
export const deleteUserMembership = async (context: ImportContext, id: string | null, groupId: unknown) => {
  if (isMissing(id) || isMissing(groupId)) {
    context.logger.warn('[opencti_user] Missing parameters: id and group_id');
    return;
  }
  await context.client.query(USER_DELETE_MEMBERSHIP, { id, group_id: groupId });
};

// pycti user.add_organization
export const addUserOrganization = async (context: ImportContext, id: string | null, organizationId: unknown) => {
  if (isMissing(id) || isMissing(organizationId)) {
    context.logger.warn('[opencti_user] Missing parameters: id and organization_id');
    return;
  }
  await context.client.query(USER_ADD_ORGANIZATION, { id, organization_id: organizationId });
};

// pycti user.delete_organization
export const deleteUserOrganization = async (context: ImportContext, id: string | null, organizationId: unknown) => {
  if (isMissing(id) || isMissing(organizationId)) {
    context.logger.warn('[opencti_user] Missing parameters: id and organization_id');
    return;
  }
  await context.client.query(USER_DELETE_ORGANIZATION, { id, organization_id: organizationId });
};

// pycti user.send_mail
export const sendUserMail = async (context: ImportContext, id: string | null, templateId: unknown) => {
  if (isMissing(id) || isMissing(templateId)) {
    context.logger.warn('[opencti_user] Missing parameters: id and template_id');
    return;
  }
  await context.client.query(SEND_USER_MAIL, { input: { target_user_id: id, email_template_id: templateId } });
};
// endregion

// region notification
const NOTIFICATION_DELETE = `
  mutation notificationDelete($id: ID!) {
    notificationDelete(id: $id)
  }
`;
const NOTIFICATION_MARK_READ = `
  mutation notificationMarkRead($id: ID!, $read: Boolean!) {
    notificationMarkRead(id: $id, read: $read) { id }
  }
`;

// pycti notification.mark_as_read
const markNotificationAsRead = async (context: ImportContext, id: string | null, read: boolean) => {
  await context.client.query(NOTIFICATION_MARK_READ, { id, read });
};

// pycti notification.update_field: only the read flag is patched
export const updateNotificationField = async (context: ImportContext, id: string | null, input: any[] | null) => {
  if (isMissing(input)) {
    return;
  }
  for (const inputValue of iterate(input)) {
    if (required(inputValue, 'key') === 'is_read') {
      await markNotificationAsRead(context, id, pythonTruthy(first(required(inputValue, 'value'))));
    }
  }
};

// pycti notification.delete (no check of the id)
const deleteNotification = async (context: ImportContext, id: string | null) => {
  await context.client.query(NOTIFICATION_DELETE, { id });
};
// endregion

// region other internal objects
const GROUP_DELETE = `
  mutation GroupDelete($id: ID!) {
    groupEdit(id: $id) { delete }
  }
`;
const ROLE_DELETE = `
  mutation RoleDelete($id: ID!) {
    roleEdit(id: $id) { delete }
  }
`;
const WORK_DELETE = `
  mutation ConnectorWorksMutation($workId: ID!) {
    workEdit(id: $workId) { delete }
  }
`;
const DELETE_OPERATION_CONFIRM = `
  mutation DeleteOperationConfirm($id: ID!) {
    deleteOperationConfirm(id: $id)
  }
`;
const DELETE_OPERATION_RESTORE = `
  mutation DeleteOperationRestore($id: ID!) {
    deleteOperationRestore(id: $id)
  }
`;
const DRAFT_WORKSPACE_DELETE = `
  mutation DraftWorkspaceDelete($id: ID!) {
    draftWorkspaceDelete(id: $id)
  }
`;
const PLAYBOOK_DELETE = `
  mutation PlaybookDelete($id: ID!) {
    playbookDelete(id: $id)
  }
`;
const PLAYBOOK_EXECUTE = `
  mutation PlaybookExecute($playbook_id: ID!, $entity_id: String!) {
    playbookExecute(id: $playbook_id, entityId: $entity_id)
  }
`;
const WORKSPACE_DELETE = `
  mutation WorkspaceDelete($id: ID!) {
    workspaceDelete(id: $id)
  }
`;
const PUBLIC_DASHBOARD_DELETE = `
  mutation PublicDashboardDelete($id: ID!) {
    publicDashboardDelete(id: $id)
  }
`;
const INTERNAL_FILE_DELETE = `
  mutation InternalFileDelete($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;
const PIR_FLAG_ELEMENT = `
  mutation PirFlagElement($id: ID!, $input: PirFlagElementInput!) {
    pirFlagElement(id: $id, input: $input)
  }
`;
const PIR_UNFLAG_ELEMENT = `
  mutation PirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
    pirUnflagElement(id: $id, input: $input)
  }
`;

// pycti group.delete
const deleteGroup = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.warn('[opencti_group] Cannot delete group, missing parameter: id');
    return;
  }
  await context.client.query(GROUP_DELETE, { id });
};

// pycti role.delete
const deleteRole = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.warn('[opencti_role] Missing parameter: id');
    return;
  }
  await context.client.query(ROLE_DELETE, { id });
};

// pycti work.delete
const deleteWork = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.warn('[opencti_work] Cannot delete work, missing parameter: id');
    return;
  }
  await context.client.query(WORK_DELETE, { workId: id });
};

// pycti trash.delete
const confirmDeleteOperation = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.warn('[opencti_trash] Cannot confirm delete, missing parameter: id');
    return;
  }
  await context.client.query(DELETE_OPERATION_CONFIRM, { id });
};

// pycti trash.restore
export const restoreDeleteOperation = async (context: ImportContext, operationId: string) => {
  await context.client.query(DELETE_OPERATION_RESTORE, { id: operationId });
};

// pycti draft.delete
const deleteDraftWorkspace = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_draft] Cannot delete draft workspace, missing parameter: id');
    return;
  }
  await context.client.query(DRAFT_WORKSPACE_DELETE, { id });
};

// pycti playbook.delete
const deletePlaybook = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_playbook] Cannot delete playbook, missing parameter: id');
    return;
  }
  await context.client.query(PLAYBOOK_DELETE, { id });
};

// pycti playbook.playbook_execute
export const executePlaybook = async (context: ImportContext, playbookId: unknown, entityId: unknown) => {
  await context.client.query(PLAYBOOK_EXECUTE, { playbook_id: playbookId, entity_id: entityId });
};

// pycti workspace.delete
const deleteWorkspace = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.warn('[opencti_workspace] Cannot delete workspace, missing parameter: id');
    return;
  }
  await context.client.query(WORKSPACE_DELETE, { id });
};

// pycti public_dashboard.delete
const deletePublicDashboard = async (context: ImportContext, id: string | null) => {
  if (isMissing(id)) {
    context.logger.error('[opencti_public_dashboard] Cannot delete public dashboard, missing parameter: id');
    return;
  }
  await context.client.query(PUBLIC_DASHBOARD_DELETE, { id });
};

// pycti internal_file.delete: the file name is the id of the extension
const deleteInternalFile = async (context: ImportContext, _id: string | null, item: StixObject) => {
  const fileName = getAttributeInExtension('id', item);
  if (fileName === null) {
    context.logger.error('[opencti_internal_file] Cannot delete internal file, missing parameters: fileName');
    return;
  }
  await context.client.query(INTERNAL_FILE_DELETE, { fileName });
};

// pycti pir.pir_flag_element
export const pirFlagElement = async (context: ImportContext, id: unknown, input: unknown) => {
  await context.client.query(PIR_FLAG_ELEMENT, { id, input });
};

// pycti pir.pir_unflag_element
export const pirUnflagElement = async (context: ImportContext, id: unknown, input: unknown) => {
  await context.client.query(PIR_UNFLAG_ELEMENT, { id, input });
};
// endregion

type InternalDelete = (context: ImportContext, id: string | null, item: StixObject) => Promise<void>;

// pycti get_internal_helper, reduced to the helpers that have a delete method (capability and
// settings have none, so deleting them fails as pycti does)
export const INTERNAL_DELETES = new Map<string, InternalDelete>([
  ['user', deleteUser],
  ['group', deleteGroup],
  ['role', deleteRole],
  ['work', deleteWork],
  ['deleteoperation', confirmDeleteOperation],
  ['draftworkspace', deleteDraftWorkspace],
  ['playbook', deletePlaybook],
  ['workspace', deleteWorkspace],
  ['publicdashboard', deletePublicDashboard],
  ['notification', deleteNotification],
  ['internalfile', deleteInternalFile],
]);
