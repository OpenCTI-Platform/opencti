import { useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Drawer from '../../../common/drawer/Drawer';
import { Investigation, InvestigationWorkSorted } from './investigation-enrichment.types';
import InvestigationEnrichmentLaunch from './InvestigationEnrichmentLaunch';
import InvestigationEnrichmentDrawerTabs, { TabList } from './InvestigationEnrichmentDrawerTabs';
import InvestigationEnrichmentWorkList from './InvestigationEnrichmentWorkList';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useInvestigationEnrichmentRights from './useInvestigationEnrichmentRights';

interface InvestigationEnrichmentDrawerProps {
  open: boolean;
  onClose: () => void;
  investigation: Investigation;
  works: InvestigationWorkSorted;
  askRefresh: () => void;
}

const InvestigationEnrichmentDrawer = ({
  open,
  onClose,
  investigation,
  works,
  askRefresh,
}: InvestigationEnrichmentDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [tab, setTab] = useState<TabList>('toreview');
  const { canLaunch } = useInvestigationEnrichmentRights(investigation.currentUserAccessRight);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const hasSelection = selectedNodes.length > 0 || selectedLinks.length > 0;

  return (
    <Drawer
      title={t_i18n('Enrichment')}
      open={open}
      onClose={onClose}
    >
      <>
        {hasSelection && canLaunch && (
          <InvestigationEnrichmentLaunch
            onCompleted={askRefresh}
            investigationId={investigation.id}
          />
        )}

        <InvestigationEnrichmentDrawerTabs
          current={tab}
          onChange={setTab}
          works={works}
        />

        <InvestigationEnrichmentWorkList
          works={works[tab]}
          worksType={tab}
          investigation={investigation}
          onWorkDeleted={askRefresh}
          onDimiss={askRefresh}
          onReview={console.log}
          onAddAll={console.log}
          onEnrichment={() => {
            askRefresh();
            setTab('ongoing');
          }}
        />
      </>
    </Drawer>
  );
};

export default InvestigationEnrichmentDrawer;
