import useGranted, { KNOWLEDGE_KNUPDATE_KNORGARESTRICT } from './useGranted';
import useEnterpriseEdition from './useEnterpriseEdition';
import useDraftContext from './useDraftContext';
import { useGetCurrentUserAccessRight } from '../authorizedMembers';

type Access = {
  currentUserAccessRight: string | null | undefined,
  authorized_members: unknown[] | undefined,
};

/**
 * In the case of an entity where there is the sharing button
 * this function returns whether organization sharing should be disabled or not
 * Organization sharing should be disabled if:
 * - platform not EE
 * - we are in a draft context
 * - the user has not the right capability
 * - in a container, if the container is under authorized members
 *
 * @param entity: the entity to share
 * @params enableManageAuthorizedMembers: if managing authorized members is enabled
 * @returns isOrgaSharingPossible: a boolean indicating if the sharing is possible
 */
const useIsOrgaSharingPossible = <T extends Access>(
  entity: T,
  isContainer: boolean,
  enableManageAuthorizedMembers = false, // only used if isContainer=true
) => {
  const userIsOrganizationEditor = useGranted([KNOWLEDGE_KNUPDATE_KNORGARESTRICT]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const draftContext = useDraftContext();
  const currentAccessRight = useGetCurrentUserAccessRight(entity.currentUserAccessRight);

  const containerRestriction = isContainer
    ? (!enableManageAuthorizedMembers && !currentAccessRight.canEdit)
      || (enableManageAuthorizedMembers && entity.authorized_members && entity.authorized_members.length > 0)
    : false;

  const isOrgaSharingPossible = isEnterpriseEdition
    && !draftContext
    && userIsOrganizationEditor
    && !containerRestriction;
  return isOrgaSharingPossible;
};

export default useIsOrgaSharingPossible;
