import { Badge, BadgeProps } from '@filigran/design-system';
import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { Investigation, InvestigationWorkSorted } from './investigation-enrichment.types';
import useInvestigationEnrichmentRights from './useInvestigationEnrichmentRights';
import { useGraphContext } from '../../../../../components/graph/GraphContext';

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

  const ongoingSize = [...works.ongoing.values()].flat().length;
  const toreviewSize = [...works.toreview.values()].flat().length;

  const hasOngoing = ongoingSize > 0;
  const hasToReview = toreviewSize > 0;
  const showBadge = hasOngoing || hasToReview || haveWorksInErrors;

  let badgeColor: BadgeProps['tone'] = 'error';
  if (hasOngoing) badgeColor = 'brand';
  if (hasToReview) badgeColor = 'success';

  let badgeContent: BadgeProps['content'] = undefined;
  if (hasOngoing) badgeContent = ongoingSize;
  if (hasToReview) badgeContent = toreviewSize;

  return (
    <Badge
      content={badgeContent}
      circularAnchor
      tone={badgeColor}
      accessibleText={false}
      invisible={!showBadge}
    >
      <GraphToolbarItem
        color="primary"
        title={t_i18n('Enrichment')}
        Icon={<CloudRefreshOutline />}
        disabled={disabled}
        onClick={onClick}
      />
    </Badge>
  );
};

export default InvestigationEnrichmentButton;
