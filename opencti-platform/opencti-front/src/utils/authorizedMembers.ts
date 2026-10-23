import { FieldOption } from './field';

export const INPUT_AUTHORIZED_MEMBERS = 'restricted_members';

export type AccessRight = 'none' | 'view' | 'use' | 'edit' | 'admin';

export interface AuthorizedMemberOption extends FieldOption {
  accessRight: AccessRight;
  groupsRestriction: FieldOption[];
}

export const CAN_USE_ENTITY_TYPES = ['Organization'];

// Entity types that support authorized members (mirrors the backend's
// AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES, plus DraftWorkspace which has its
// own dedicated authorized members mechanism).
export const AUTHORIZED_MEMBERS_ENTITY_TYPES = [
  'Organization',
  'Report',
  'Note',
  'Grouping',
  'Case-Incident',
  'Case-Rft',
  'Case-Rfi',
  'DraftWorkspace',
];

export const ALL_MEMBERS_AUTHORIZED_CONFIG = {
  id: 'ALL',
  labelKey: 'Everyone on the platform',
  type: 'Dynamic options',
};

export const CREATOR_AUTHORIZED_CONFIG = {
  id: 'CREATOR',
  labelKey: 'Creator',
  type: 'Dynamic options',
};

export type AuthorizedMembers = ReadonlyArray<{
  readonly access_right: string;
  readonly entity_type: string;
  readonly id: string;
  readonly member_id: string;
  readonly name: string;
  readonly groups_restriction: ReadonlyArray<{
    readonly id: string;
    readonly name: string;
  }> | null | undefined;
}> | null;

export type Creator = {
  readonly id: string;
  readonly name: string;
  readonly entity_type: string;
};

/**
 * Transform data into format used by Formik field.
 *
 * @param authorizedMembers Data from backend.
 */
export const authorizedMembersToOptions = (
  authorizedMembers: AuthorizedMembers,
): AuthorizedMemberOption[] | null => {
  if (!authorizedMembers) return null;

  return authorizedMembers
    .map((member) => {
      return {
        label: member.name,
        type: member.entity_type,
        value: member.member_id || member.id,
        accessRight: member.access_right as AccessRight,
        groupsRestriction: (member.groups_restriction ?? []).map((o) => {
          return {
            label: o.name,
            value: o.id,
          };
        }),
      };
    });
};

export interface MemberAccessInput {
  id: string;
  access_right: AccessRight;
  groups_restriction_ids?: string[];
}

/**
 * Transform the Formik field value into the input of the backend mutations.
 * Members without access are dropped. The groups restriction is kept per member:
 * an organization restricted to a group and the same organization without restriction are two rules.
 *
 * @param authorizedMembers Value of the Formik field.
 */
export const authorizedMembersToInput = (
  authorizedMembers: AuthorizedMemberOption[] | null | undefined,
): MemberAccessInput[] => {
  return (authorizedMembers ?? [])
    .filter((member) => member.accessRight !== 'none')
    .map((member) => {
      return {
        id: member.value,
        access_right: member.accessRight,
        groups_restriction_ids: member.groupsRestriction?.length > 0
          ? member.groupsRestriction.map((group) => group.value)
          : undefined,
      };
    });
};

export const useGetCurrentUserAccessRight = (userAccessRight: string | null | undefined) => {
  const canManage = userAccessRight === 'admin';
  const canEdit = canManage || userAccessRight === 'edit';
  const canUse = canManage || userAccessRight === 'use';
  const canView = canManage || canEdit || userAccessRight === 'view';
  return { canManage, canEdit, canUse, canView };
};

export const getMaximumUserAccessRight = (userAccessRights: Array<string | null | undefined>) => {
  if (userAccessRights.some((m) => m === 'admin')) {
    return 'admin';
  }
  if (userAccessRights.some((m) => m === 'edit')) {
    return 'edit';
  }
  if (userAccessRights.some((m) => m === 'use')) {
    return 'use';
  }
  if (userAccessRights.some((m) => m === 'view')) {
    return 'view';
  }
  return null;
};

export const canUse = (userAccessRights: Array<string | null | undefined>) => {
  const maximumAccessRight = getMaximumUserAccessRight(userAccessRights);
  return maximumAccessRight !== null && maximumAccessRight !== 'view';
};
