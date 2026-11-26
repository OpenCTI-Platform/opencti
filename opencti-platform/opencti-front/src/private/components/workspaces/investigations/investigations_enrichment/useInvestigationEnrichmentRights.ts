import useGranted, { INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';

/**
 * - canEdit: change the investigation from its enrichments (run a connector again on an entity, add the results to the graph,
 *   mark them as reviewed, delete them), all checked by validateEnrichmentInvestigation on the server: without it, these actions are hidden,
 * - canLaunch: start a bulk enrichment on the selection, a knowledge background task which also needs KNOWLEDGE_KNUPDATE.
 */
const useInvestigationEnrichmentRights = (currentUserAccessRight: string | null | undefined) => {
  const { canEdit: canEditAccess } = useGetCurrentUserAccessRight(currentUserAccessRight);
  const canEnrichInvestigation = useGranted([INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT], true);
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);

  const canEdit = canEditAccess && canEnrichInvestigation;

  return {
    canEdit,
    canLaunch: canEdit && canUpdateKnowledge,
  };
};

export default useInvestigationEnrichmentRights;
