import useGranted, { INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';

/**
 * - canEdit: change the investigation from its enrichments (add the results to the graph, mark them as reviewed, delete them),
 *   which the server allows with the same rights as canRefresh: without them, these actions are hidden,
 * - canRefresh: run a connector again on an entity (askEnrichment linked to the investigation),
 * - canLaunch: start a bulk enrichment on the selection, a knowledge background task which also needs KNOWLEDGE_KNUPDATE.
 */
const useInvestigationEnrichmentRights = (currentUserAccessRight: string | null | undefined) => {
  const { canEdit: canEditAccess } = useGetCurrentUserAccessRight(currentUserAccessRight);
  const canEnrichInvestigation = useGranted([INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT], true);
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);

  const canRefresh = canEditAccess && canEnrichInvestigation;

  return {
    canEdit: canRefresh,
    canRefresh,
    canLaunch: canRefresh && canUpdateKnowledge,
  };
};

export default useInvestigationEnrichmentRights;
