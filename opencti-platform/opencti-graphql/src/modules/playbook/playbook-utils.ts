import * as R from 'ramda';
import { isEmptyField } from '../../database/utils';
import { AUTOMATION_MANAGER_USER, executionContext, INTERNAL_USERS } from '../../utils/access';
import { getEntitiesListFromCache } from '../../database/cache';
import type { AuthUser } from '../../types/user';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { StixBundle, StixObject } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { FunctionalError } from '../../config/errors';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';

export const extractBundleBaseElement = (instanceId: string, bundle: StixBundle): StixObject => {
  const baseData = bundle.objects.find((o) => o.id === instanceId);
  if (!baseData) throw FunctionalError('Playbook base element no longer accessible');
  return baseData;
};

export const convertMembersToUsers = async (members: { value: string }[], baseData: StixObject, bundle: StixBundle) => {
  if (isEmptyField(members)) {
    return [];
  }
  const context = executionContext('playbook_components');
  const platformUsers = await getEntitiesListFromCache<AuthUser>(context, AUTOMATION_MANAGER_USER, ENTITY_TYPE_USER);

  const membersIds: string[] = [];
  members?.forEach((m) => {
    if (m.value === 'AUTHOR') {
      membersIds.push(baseData.extensions[STIX_EXT_OCTI].created_by_ref_id);
    } else if (m.value === 'CREATORS') {
      const creatorIds = baseData.extensions[STIX_EXT_OCTI].creator_ids;
      membersIds.push(...creatorIds);
    } else if (m.value === 'ASSIGNEES') {
      const assigneeIds = baseData.extensions[STIX_EXT_OCTI].assignee_ids;
      membersIds.push(...assigneeIds);
    } else if (m.value === 'PARTICIPANTS') {
      const participantIds = baseData.extensions[STIX_EXT_OCTI].participant_ids;
      membersIds.push(...participantIds);
    } else if (m.value === 'BUNDLE_ORGANIZATIONS') {
      const bundleOrganizations = bundle.objects.filter((o) => o.extensions[STIX_EXT_OCTI].type === ENTITY_TYPE_IDENTITY_ORGANIZATION);
      const bundleOrganizationsIds = bundleOrganizations.map((o) => o.extensions[STIX_EXT_OCTI].id);
      membersIds.push(...bundleOrganizationsIds);
    } else {
      membersIds.push(m.value);
    }
  });

  const usersFromGroups = platformUsers.filter((user) => user.groups.map((g) => g.internal_id)
    .some((id: string) => membersIds.includes(id)));
  const usersFromOrganizations = platformUsers.filter((user) => user.organizations.map((g) => g.internal_id)
    .some((id: string) => membersIds.includes(id)));
  const usersFromIds = platformUsers.filter((user) => membersIds.includes(user.id));
  const withoutInternalUsers = [...usersFromOrganizations, ...usersFromGroups, ...usersFromIds]
    .filter((u) => INTERNAL_USERS[u.id] === undefined);
  return R.uniqBy(R.prop('id'), withoutInternalUsers);
};
