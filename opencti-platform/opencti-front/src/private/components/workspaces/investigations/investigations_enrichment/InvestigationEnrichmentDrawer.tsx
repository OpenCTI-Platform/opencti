import { useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
import Drawer from '../../../common/drawer/Drawer';
import { Investigation, InvestigationEnrichmentWork, InvestigationWorkSorted } from './investigation-enrichment.types';
import InvestigationEnrichmentLaunch from './InvestigationEnrichmentLaunch';
import InvestigationEnrichmentDrawerTabs, { TabList } from './InvestigationEnrichmentDrawerTabs';
import InvestigationEnrichmentWorkList from './InvestigationEnrichmentWorkList';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useInvestigationEnrichmentRights from './useInvestigationEnrichmentRights';
import InvestigationEnrichmentExpand from './InvestigationEnrichmentExpand';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import { InvestigationEnrichmentDrawerDismissReview } from './__generated__/InvestigationEnrichmentDrawerDismissReview.graphql';
import { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';
import useInvestigationEnrichmentExpand from './useInvestigationEnrichmentExpand';
import InvestigationEnrichmentAddAllDialog from './InvestigationEnrichmentAddAllDialog';
import { isNothingToExpand, toExpandElements } from './investigation-enrichment.utils';

const dismissReviewMutation = graphql`
  mutation InvestigationEnrichmentDrawerDismissReview($workId: ID!, $status: WorkInvestigationStatus!) {
    workInvestigationStatusEdit(id: $workId, status: $status) {
      id
      investigation_status
    }
  }
`;

interface InvestigationEnrichmentDrawerProps {
  open: boolean;
  onClose: () => void;
  investigation: Investigation;
  works: InvestigationWorkSorted;
  askRefresh: () => void;
  onExpand?: (newObjects: ObjectToParse[]) => void;
}

const InvestigationEnrichmentDrawer = ({
  open,
  onClose,
  investigation,
  works,
  askRefresh,
  onExpand,
}: InvestigationEnrichmentDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [tab, setTab] = useState<TabList>('toreview');
  const [workToReview, setWorkToReview] = useState<InvestigationEnrichmentWork>();
  const [workToAddAll, setWorkToAddAll] = useState<InvestigationEnrichmentWork>();

  const {
    graphIds,
    expandWork,
  } = useInvestigationEnrichmentExpand(investigation.id, onExpand);
  const { canLaunch, canEdit } = useInvestigationEnrichmentRights(investigation.currentUserAccessRight);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const hasSelection = selectedNodes.length > 0 || selectedLinks.length > 0;

  const [commitDismiss] = useApiMutation<InvestigationEnrichmentDrawerDismissReview>(
    dismissReviewMutation,
  );
  const dismissReview = (workId: string) => {
    setWorkToReview(undefined);
    commitDismiss({
      variables: { workId: workId, status: 'DONE' },
      onCompleted: () => askRefresh(),
    });
  };

  /**
   * Shortcut of a review that ticks every type and expands: adds all the
   * touched elements to the graph, then marks the work as reviewed.
   */
  const addAll = async (work: InvestigationEnrichmentWork) => {
    await expandWork(work);
    dismissReview(work.id);
  };

  return (
    <>
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
            onDimiss={dismissReview}
            onReview={setWorkToReview}
            onAddAll={setWorkToAddAll}
            onEnrichment={() => {
              askRefresh();
              setTab('ongoing');
            }}
          />
        </>
      </Drawer>

      <InvestigationEnrichmentExpand
        investigationId={investigation.id}
        work={workToReview}
        onClose={() => setWorkToReview(undefined)}
        onDismiss={dismissReview}
        onExpand={onExpand}
        canEdit={canEdit}
      />

      <InvestigationEnrichmentAddAllDialog
        work={workToAddAll}
        nothingToAdd={isNothingToExpand(toExpandElements(workToAddAll), graphIds)}
        canEdit={canEdit}
        onConfirm={addAll}
        onDismiss={dismissReview}
        onClose={() => setWorkToAddAll(undefined)}
      />
    </>
  );
};

export default InvestigationEnrichmentDrawer;
