import { useState } from 'react';
import { graphql } from 'react-relay';
import { Button } from '@filigran/design-system';
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
import Security from '../../../../../utils/Security';

const dismissReviewMutation = graphql`
  mutation InvestigationEnrichmentDrawerDismissReview($workId: ID!, $status: WorkInvestigationStatus!) {
    workInvestigationStatusEdit(workId: $workId, status: $status) {
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
  const [worksToReview, setWorksToReview] = useState<InvestigationEnrichmentWork[]>([]);
  const [workToAddAll, setWorkToAddAll] = useState<InvestigationEnrichmentWork>();

  const {
    graphIds,
    expandWorks,
  } = useInvestigationEnrichmentExpand(investigation.id, onExpand);
  const { canLaunch, canEdit } = useInvestigationEnrichmentRights(investigation.currentUserAccessRight);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const hasSelection = selectedNodes.length > 0 || selectedLinks.length > 0;

  const [commitDismiss] = useApiMutation<InvestigationEnrichmentDrawerDismissReview>(
    dismissReviewMutation,
  );
  /**
   * Marks works as reviewed, then refreshes the list once they all answered.
   */
  const dismissReviews = (workIds: string[]) => {
    setWorksToReview([]);
    let pending = workIds.length;
    const onSettled = () => {
      pending -= 1;
      if (pending === 0) {
        askRefresh();
      }
    };
    workIds.forEach((workId) => {
      commitDismiss({
        variables: { workId, status: 'DONE' },
        onCompleted: onSettled,
        onError: onSettled,
      });
    });
  };

  /**
   * Marks a work as reviewed.
   */
  const dismissReview = (workId: string) => dismissReviews([workId]);

  // The works a review of all covers: those in error have no results, their own review is disabled.
  const reviewableWorks = [...works.toreview.values()]
    .flat()
    .filter((work) => (work.errors ?? []).length === 0);

  /**
   * Shortcut of a review that ticks every type and expands: adds all the
   * touched elements to the graph, then marks the work as reviewed.
   */
  const addAll = async (work: InvestigationEnrichmentWork) => {
    await expandWorks([work]);
    dismissReview(work.id);
  };

  return (
    <>
      <Drawer
        title={t_i18n('Enrichment')}
        open={open}
        onClose={onClose}
        // The review and add all dialogs trap the focus themselves (see Drawer).
        disableEnforceFocus={worksToReview.length > 0 || !!workToAddAll}
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

          {tab === 'toreview' && reviewableWorks.length > 0 && (
            // Same rights as the review of one work, in its row of the list.
            <Security needs={['CONNECTORAPI', 'MODULES_MODMANAGE']}>
              <div className="flex justify-end">
                <Button
                  priority="secondary"
                  onClick={() => setWorksToReview(reviewableWorks)}
                >
                  {t_i18n('Review all')} ({reviewableWorks.length})
                </Button>
              </div>
            </Security>
          )}

          <InvestigationEnrichmentWorkList
            works={works[tab]}
            worksType={tab}
            investigation={investigation}
            onWorkDeleted={askRefresh}
            onDimiss={dismissReview}
            onReview={(work) => setWorksToReview([work])}
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
        works={worksToReview}
        onClose={() => setWorksToReview([])}
        onDismiss={dismissReviews}
        onExpand={onExpand}
        canEdit={canEdit}
      />

      <InvestigationEnrichmentAddAllDialog
        work={workToAddAll}
        nothingToAdd={isNothingToExpand(toExpandElements(workToAddAll ? [workToAddAll] : []), graphIds)}
        canEdit={canEdit}
        onConfirm={addAll}
        onDismiss={dismissReview}
        onClose={() => setWorkToAddAll(undefined)}
      />
    </>
  );
};

export default InvestigationEnrichmentDrawer;
