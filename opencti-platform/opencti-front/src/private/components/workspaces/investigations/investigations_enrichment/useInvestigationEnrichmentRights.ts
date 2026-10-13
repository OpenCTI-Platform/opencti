import useGranted, { INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';

/**
 * - canRefresh: run a connector again on an entity (askEnrichment linked to the investigation),
 * - canLaunch: start a bulk enrichment on the selection, a knowledge background task which also needs KNOWLEDGE_KNUPDATE.
 */
const useInvestigationEnrichmentRights = (currentUserAccessRight: string | null | undefined) => {
  const { canEdit } = useGetCurrentUserAccessRight(currentUserAccessRight);
  const canEnrichInvestigation = useGranted([INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT], true);
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);

  const canRefresh = canEdit && canEnrichInvestigation;

  return {
    canRefresh,
    canLaunch: canRefresh && canUpdateKnowledge,
  };
};

export default useInvestigationEnrichmentRights;
