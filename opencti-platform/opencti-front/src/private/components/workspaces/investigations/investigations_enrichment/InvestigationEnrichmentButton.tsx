import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { Investigation } from './investigation-enrichment.types';
import useGranted, { INVESTIGATION_INUPDATE } from '../../../../../utils/hooks/useGranted';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { useMemo } from 'react';

interface InvestigationEnrichmentButtonProps {
  onClick: () => void;
  investigation: Investigation;
}

const InvestigationEnrichmentButton = ({
  onClick,
  investigation,
}: InvestigationEnrichmentButtonProps) => {
  const { t_i18n } = useFormatter();
  const canUpdate = useGranted([INVESTIGATION_INUPDATE]);
  const { canEdit } = useGetCurrentUserAccessRight(investigation?.currentUserAccessRight);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const selection = [...selectedNodes, ...selectedLinks];
  const hasSelection = selection.length > 0;

  const worksStatus = useMemo(() => {
    const worksStatus = new Set<string>();
    if (investigation) {
      investigation.enrichmentWorks?.edges?.forEach((work) => {
        if (work && work.node) worksStatus.add(work.node.status);
      });
    }
    return worksStatus;
  }, [investigation]);

  console.log(worksStatus);

  // TODO back : new field for investigation status

  return (
    <GraphToolbarItem
      color="primary"
      title={t_i18n('Enrichment')}
      Icon={<CloudRefreshOutline />}
      disabled={!canEdit || !canUpdate || !hasSelection}
      onClick={onClick}
    />
  );
};

export default InvestigationEnrichmentButton;
