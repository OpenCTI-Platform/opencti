import * as R from 'ramda';
import { isEmptyField } from '../../database/utils';
import { AUTOMATION_MANAGER_USER, executionContext, isInternalUser } from '../../utils/access';
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

/**
 * Returns the list of all users authorized based on given members array.
 *
 * @param members Array of members.
 * @param baseData Data from event.
 * @param bundle Stix bundle transiting through playbook components.
 * @returns List of users.
 */
export const convertMembersToUsers = async (
  members: { value: string }[],
  baseData: StixObject,
  bundle: StixBundle
) => {
  if (isEmptyField(members)) return [];
  const platformUsers = await getEntitiesListFromCache<AuthUser>(
    executionContext('playbook_components'),
    AUTOMATION_MANAGER_USER,
    ENTITY_TYPE_USER
  );

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

  const users = platformUsers.filter((user) => {
    if (isInternalUser(user)) return false;
    const isDirectlyAuthorized = membersIds.includes(user.id);
    const isAuthorizedByGroup = user.groups.some((g) => membersIds.includes(g.internal_id));
    const isAuthorizedByOrganization = user.organizations.some((o) => membersIds.includes(o.internal_id));
    return isDirectlyAuthorized || isAuthorizedByGroup || isAuthorizedByOrganization;
  });
  return R.uniqBy(R.prop('id'), users);
};
