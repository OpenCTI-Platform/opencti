import useGranted, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from './useGranted';
import useEnterpriseEdition from './useEnterpriseEdition';
import useDraftContext from './useDraftContext';
import { useGetCurrentUserAccessRight } from '../authorizedMembers';
import { useFormatter } from '../../components/i18n';

/**
 * Helper function returning whether organization sharing should be disabled or not
 * Organization sharing should be disabled if:
 * - platform not EE
 * - we are in a draft context
 * - the user has not the right capability
 * - in a container, if the container is under authorized members
 *
 * @param entity: the entity to share
 * @params enableManageAuthorizedMembers: if managing authorized members is enabled
 * @returns isSharingNotPossible: a boolean indicating if the sharing is possible
 * @returns sharingNotPossibleMessage: the message explanation if it is not shareable
 */
const useSharingDisabled = <T extends {
  currentUserAccessRight: string | null | undefined,
  authorized_members: {
    value: string,
    accessRight: string,
    groupsRestriction: {
      label: string,
      value: string,
      type: string
    }[] }[] | undefined,
}>(
    entity: T,
    isContainer: boolean,
    enableManageAuthorizedMembers?: boolean, // only used if isContainer=true
  ) => {
  const { t_i18n } = useFormatter();
  const userIsOrganizationEditor = useGranted([KNOWLEDGE_KNUPDATE_KNORGARESTRICT]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(entity.currentUserAccessRight);

  const containerRestriction = isContainer
    ? (!enableManageAuthorizedMembers && !currentAccessRight.canEdit)
      || (enableManageAuthorizedMembers && entity.authorized_members && entity.authorized_members.length > 0)
    : false;

  const isSharingNotPossible = !isEnterpriseEdition
    || !!draftContext
    || !userIsOrganizationEditor
    || containerRestriction;
  let sharingNotPossibleMessage;
  if (isSharingNotPossible) {
    sharingNotPossibleMessage = draftContext
      ? t_i18n('Not available in draft')
      : t_i18n('You are not allowed to do this');
  }
  return { isSharingNotPossible, sharingNotPossibleMessage };
};

export default useSharingDisabled;
