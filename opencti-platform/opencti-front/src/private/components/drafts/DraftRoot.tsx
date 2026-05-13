import React, { Suspense, useEffect, useState } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import DraftEntities from '@components/drafts/DraftEntities';
import DraftRelationships from '@components/drafts/DraftRelationships';
import DraftSightings from '@components/drafts/DraftSightings';
import DraftReview from '@components/drafts/DraftReview';
import { DraftRootQuery } from '@components/drafts/__generated__/DraftRootQuery.graphql';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { interval } from 'rxjs';
import ConnectorWorkLine from '@components/data/connectors/ConnectorWorkLine';
import Paper from '@mui/material/Paper';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import ImportFilesContent from '@components/data/import/ImportFilesContent';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';
import { getCurrentTab } from '../../../utils/tabUtils';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { TEN_SECONDS } from '../../../utils/Time';
import useGranted, { KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import useSwitchDraft from './useSwitchDraft';
import { DraftRootFragment$key } from './__generated__/DraftRootFragment.graphql';
import DraftOverview from '@components/drafts/DraftOverview';
import useHelper from '../../../utils/hooks/useHelper';
import Dialog from '@common/dialog/Dialog';
import Button from '../../../components/common/button/Button';

const interval$ = interval(TEN_SECONDS);

const DRAFT_COMMENT_SEEN_PREFIX = 'opencti-draft-comment-seen-';

const draftRootQuery = graphql`
  query DraftRootQuery($id: String!) {
    draftWorkspace(id: $id) {
      ...DraftRootFragment
    }
  }
`;

export const draftRootFragment = graphql`
  fragment DraftRootFragment on DraftWorkspace {
    id
    name
    entity_type
    description
    created_at
    objectAssignee {
      id
      name
      entity_type
    }
    objectParticipant {
      id
      name
      entity_type
    }
    createdBy {
      id
      name
      entity_type
    }
    objectsCount {
      containersCount
      entitiesCount
      observablesCount
      relationshipsCount
      sightingsCount
      reviewsCount
      totalCount
    }
    draft_status
    currentUserAccessRight
    authorizedMembers {
      id
      name
      entity_type
      access_right
      member_id
      groups_restriction {
        id
        name
      }
    }
    validationWork {
      id
      name
      received_time
      processed_time
      completed_time
      status
      tracking {
        import_expected_number
        import_processed_number
      }
      errors {
        timestamp
        message
        sequence
        source
      }
    }
    workflowInstance {
      lastHistoryEntry {
        comment
        timestamp
      }
    }
  }
`;

interface RootDraftComponentProps {
  draftId: string;
  refetch: () => void;
  queryRef: PreloadedQuery<DraftRootQuery>;
}

const RootDraftComponent = ({ draftId, queryRef, refetch }: RootDraftComponentProps) => {
  const { isFeatureEnable } = useHelper();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const canAskImportKnowledge = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const [showCommentPopup, setShowCommentPopup] = useState(false);

  const { draftWorkspace: draftWorkspaceFragment } = usePreloadedQuery<DraftRootQuery>(draftRootQuery, queryRef);
  if (!draftWorkspaceFragment) {
    return (<ErrorNotFound />);
  }

  const draft = useFragment<DraftRootFragment$key>(draftRootFragment, draftWorkspaceFragment);
  const {
    name,
    objectsCount,
    draft_status,
    validationWork,
  } = draft;
  const isDraftReadOnly = draft_status !== 'open';

  // switch to draft
  const { enterDraft } = useSwitchDraft();

  useEffect(() => {
    if (!isDraftReadOnly && (!draftContext || draftContext.id !== draftId)) {
      enterDraft(draftId, {
        onCompleted: () => {
          MESSAGING$.notifySuccess(<span>{t_i18n('You are now in Draft Mode')}</span>);
        },
        onError: (error) => {
          const { errors } = (error as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        },
      });
    }
  }, [draftContext, draftId, enterDraft, isDraftReadOnly, t_i18n]);

  // Show a popup once per history entry if the last transition has a comment
  useEffect(() => {
    const lastEntry = draft.workflowInstance?.lastHistoryEntry;
    if (!lastEntry?.comment || !lastEntry?.timestamp) return;
    const storageKey = `${DRAFT_COMMENT_SEEN_PREFIX}${draftId}`;
    const seenTimestamp = window.localStorage.getItem(storageKey);
    if (seenTimestamp !== lastEntry.timestamp) {
      setShowCommentPopup(true);
      window.localStorage.setItem(storageKey, lastEntry.timestamp);
    }
  }, [draftId, draft.workflowInstance?.lastHistoryEntry?.timestamp]);

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  // If me user is not yet updated to be in draft, display loader
  if (!isDraftReadOnly && !draftContext) {
    return (<Loader />);
  }

  const basePath = `/dashboard/data/import/draft/${draftId}`;
  return (
    <>
      <Dialog
        open={showCommentPopup}
        onClose={() => setShowCommentPopup(false)}
        title={t_i18n('Last workflow comment')}
        size="large"
      >
        <DialogContentText sx={{ whiteSpace: 'pre-wrap' }}>
          {draft.workflowInstance?.lastHistoryEntry?.comment}
        </DialogContentText>
        <DialogActions>
          <Button onClick={() => setShowCommentPopup(false)}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
      {isDraftReadOnly && (
        <>
          <Breadcrumbs
            elements={[
              { label: t_i18n('Data') },
              { label: t_i18n('Import'), link: '/dashboard/data/import' },
              { label: t_i18n('Drafts'), link: '/dashboard/data/import/draft' },
              { label: name, current: true },
            ]}
          />
          {validationWork && (
            <Paper
              key={validationWork.id}
              style={{ margin: '10px 0 20px 0', padding: '15px', borderRadius: 4, position: 'relative' }}
              variant="outlined"
            >
              <ConnectorWorkLine
                workId={validationWork.id}
                workName={validationWork.name}
                workStatus={validationWork.status}
                workReceivedTime={validationWork.received_time}
                workEndTime={validationWork.completed_time}
                workExpectedNumber={validationWork.tracking?.import_processed_number}
                workProcessedNumber={validationWork.tracking?.import_expected_number}
                workErrors={validationWork.errors}
                readOnly
              />
            </Paper>
          )}
        </>
      )}
      <Box
        sx={{
          borderBottom: 1,
          borderColor: 'divider',
          marginBottom: 3,
        }}
      >
        <Tabs
          id="tabs-container"
          value={getCurrentTab(location.pathname, basePath)}
        >
          {isFeatureEnable('DRAFT_WORKFLOW') && (
            <Tab
              component={Link}
              to="overview"
              value="overview"
              label={
                <span>{t_i18n('Overview')}</span>
              }
            />
          )}
          <Tab
            component={Link}
            to="entities"
            value="entities"
            label={
              <span>{t_i18n('Entities')} ({objectsCount.entitiesCount})</span>
            }
          />
          <Tab
            component={Link}
            to="observables"
            value="observables"
            label={
              <span>{t_i18n('Observables')} ({objectsCount.observablesCount})</span>
            }
          />
          <Tab
            component={Link}
            to="relationships"
            value="relationships"
            label={
              <span>{t_i18n('Relationships')} ({objectsCount.relationshipsCount})</span>
            }
          />
          <Tab
            component={Link}
            to="sightings"
            value="sightings"
            label={
              <span>{t_i18n('Sightings')} ({objectsCount.sightingsCount})</span>
            }
          />
          <Tab
            component={Link}
            to="containers"
            value="containers"
            label={
              <span>{t_i18n('Containers')} ({objectsCount.containersCount})</span>
            }
          />
          {!isDraftReadOnly && canAskImportKnowledge && (
            <Tab
              component={Link}
              to="files"
              value="files"
              label={t_i18n('Files')}
            />
          )}
          <Tab
            component={Link}
            to="review"
            value="review"
            label={<span>{t_i18n('Review')} ({objectsCount.reviewsCount})</span>}
          />
        </Tabs>
      </Box>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/data/import/draft/${draftId}/entities`} replace={true} />}
        />
        {isFeatureEnable('DRAFT_WORKFLOW') && (
          <Route
            path="/overview"
            element={<DraftOverview draft={draft} />}
          />
        )}
        <Route
          path="/entities"
          element={<DraftEntities entitiesType="Stix-Domain-Object" excludedEntityTypes="Container" isReadOnly={isDraftReadOnly} />}
        />
        <Route
          path="/observables"
          element={<DraftEntities entitiesType="Stix-Cyber-Observable" isReadOnly={isDraftReadOnly} />}
        />
        <Route
          path="/relationships"
          element={<DraftRelationships isReadOnly={isDraftReadOnly} />}
        />
        <Route
          path="/sightings"
          element={<DraftSightings isReadOnly={isDraftReadOnly} />}
        />
        <Route
          path="/containers"
          element={<DraftEntities entitiesType="Container" isReadOnly={isDraftReadOnly} />}
        />
        <Route
          path="/files"
          element={<ImportFilesContent inDraftOverview />}
        />
        <Route
          path="/review"
          element={<DraftReview draftId={draftId} />}
        />
      </Routes>
    </>
  );
};

const RootDraft = () => {
  const { draftId } = useParams() as { draftId: string };
  const [queryRef, loadQuery] = useQueryLoader<DraftRootQuery>(draftRootQuery);
  useEffect(() => {
    loadQuery({ id: draftId }, { fetchPolicy: 'store-and-network' });
  }, [draftId, loadQuery]);

  const refetch = React.useCallback(() => {
    loadQuery({ id: draftId }, { fetchPolicy: 'store-and-network' });
  }, [draftId, loadQuery]);

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootDraftComponent draftId={draftId} queryRef={queryRef} refetch={refetch} />
        </Suspense>
      )}
    </>
  );
};

export default RootDraft;
