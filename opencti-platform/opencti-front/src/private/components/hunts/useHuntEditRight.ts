import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';

/**
 * Whether the user may change a hunt and its runs. Same rule as the edit and delete controls of the entity header, in a
 * draft the access to the draft too; the edition of the hunt only exists with the update capability, so its shortcuts
 * need it as well.
 */
const useHuntEditRight = (currentUserAccessRight: string | null | undefined) => {
  const canUpdate = useGranted([KNOWLEDGE_KNUPDATE]);
  const draftContext = useDraftContext();
  const accessRight = useGetCurrentUserAccessRight(currentUserAccessRight);
  const draftAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  return canUpdate && accessRight.canEdit && (!draftContext || draftAccessRight.canEdit);
};

export default useHuntEditRight;
