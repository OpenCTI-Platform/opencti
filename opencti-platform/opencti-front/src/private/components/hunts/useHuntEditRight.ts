import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useGranted, { KNOWLEDGE_KNHUNT, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';

/** Creating, changing, running and triaging hunts: the update of the knowledge and the hunt capability, both (matchAll). */
export const HUNT_CAPABILITIES = [KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNHUNT];

/**
 * Whether the user may change a hunt and its runs. Same rule as the edit and delete controls of the entity header, in a
 * draft the access to the draft too; the edition of the hunt only exists with the hunt capabilities, so its shortcuts
 * need them as well.
 */
const useHuntEditRight = (currentUserAccessRight: string | null | undefined) => {
  const canUpdate = useGranted(HUNT_CAPABILITIES, true);
  const draftContext = useDraftContext();
  const accessRight = useGetCurrentUserAccessRight(currentUserAccessRight);
  const draftAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);
  return canUpdate && accessRight.canEdit && (!draftContext || draftAccessRight.canEdit);
};

export default useHuntEditRight;
