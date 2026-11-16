import useGranted, { INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../../utils/hooks/useGranted';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';
import { useFormatter } from '../../../../../components/i18n';

/**
 * - canEdit: change the investigation (add the results of an enrichment to the graph),
 * - canRefresh: run a connector again on an entity (askEnrichment linked to the investigation),
 * - canLaunch: start a bulk enrichment on the selection, a knowledge background task which also needs KNOWLEDGE_KNUPDATE,
 * - reviewDisabledReason: why an editor cannot mark results as reviewed, which needs the same rights as canRefresh.
 */
const useInvestigationEnrichmentRights = (currentUserAccessRight: string | null | undefined) => {
  const { t_i18n } = useFormatter();
  const { canEdit } = useGetCurrentUserAccessRight(currentUserAccessRight);
  const canEnrichInvestigation = useGranted([INVESTIGATION_INUPDATE, KNOWLEDGE_KNENRICHMENT], true);
  const canUpdateKnowledge = useGranted([KNOWLEDGE_KNUPDATE]);

  const canRefresh = canEdit && canEnrichInvestigation;

  return {
    canEdit,
    canRefresh,
    canLaunch: canRefresh && canUpdateKnowledge,
    reviewDisabledReason: canEdit && !canEnrichInvestigation
      ? t_i18n('You need the Ask for knowledge enrichment and Create / Update investigations capabilities to review enrichment results.')
      : undefined,
  };
};

export default useInvestigationEnrichmentRights;
