import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { Investigation, InvestigationWorkSorted } from './investigation-enrichment.types';
import useInvestigationEnrichmentRights from './useInvestigationEnrichmentRights';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { PropsWithChildren } from 'react';
import { Badge } from '@filigran/design-system';

interface InvestigationEnrichmentButtonProps {
  onClick: () => void;
  investigation: Investigation;
  works: InvestigationWorkSorted;
  haveWorksInErrors: boolean;
  nbWorks: number;
}

const InvestigationEnrichmentButton = ({
  onClick,
  investigation,
  works,
  haveWorksInErrors,
  nbWorks,
}: InvestigationEnrichmentButtonProps) => {
  const { t_i18n } = useFormatter();
  const { canLaunch } = useInvestigationEnrichmentRights(investigation?.currentUserAccessRight);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;

  const hasSelection = selectedNodes.length > 0 || selectedLinks.length > 0;
  const hasWorks = nbWorks > 0;
  const disabled = !hasWorks && !(hasSelection && canLaunch);

  const BadgeWrapper = ({ children }: PropsWithChildren) => {
    if (haveWorksInErrors || works.ongoing.size > 0) {
      return (
        <Badge
          className="mt-2 mr-2"
          accessibleText={false}
          tone={haveWorksInErrors ? 'error' : 'brand'}
        >{children}
        </Badge>
      );
    }
    return <>{children}</>;
  };

  return (
    <BadgeWrapper>
      <GraphToolbarItem
        color="primary"
        title={t_i18n('Enrichment')}
        Icon={<CloudRefreshOutline />}
        disabled={disabled}
        onClick={onClick}
      />
    </BadgeWrapper>
  );
};

export default InvestigationEnrichmentButton;
