import { Option } from '@components/common/form/ReferenceField';

export const INPUT_AUTHORIZED_MEMBERS = 'authorized_members';

export type AccessRight = 'none' | 'view' | 'edit' | 'admin';

export interface AuthorizedMemberOption extends Option {
  accessRight: AccessRight
}

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
  readonly name: string;
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
        value: member.id,
        accessRight: member.access_right as AccessRight,
      };
    });
};
