import React, { FunctionComponent, Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import DraftBlock from '@components/common/draft/DraftBlock';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import DialogTitle from '@mui/material/DialogTitle';
import Dialog from '@mui/material/Dialog';
import DraftProcessingStatus from '@components/drafts/DraftProcessingStatus';
import Alert from '@mui/material/Alert';
import { AlertTitle } from '@mui/material';
import { interval } from 'rxjs';
import { DraftContextBannerQuery } from '@components/drafts/__generated__/DraftContextBannerQuery.graphql';
import { DraftContextBanner_data$key } from '@components/drafts/__generated__/DraftContextBanner_data.graphql';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { truncate } from '../../../utils/String';
import { MESSAGING$ } from '../../../relay/environment';
import Transition from '../../../components/Transition';
import { TEN_SECONDS } from '../../../utils/Time';
import Loader, { LoaderVariant } from '../../../components/Loader';
import ErrorNotFound from '../../../components/ErrorNotFound';

const interval$ = interval(TEN_SECONDS * 3);

const draftContextBannerFragment = graphql`
  fragment DraftContextBanner_data on DraftWorkspace {
      id
      name
      draft_status
      processingCount
  }
`;

const draftContextBannerQuery = graphql`
  query DraftContextBannerQuery($id: String!) {
    draftWorkspace(id: $id) {
      ...DraftContextBanner_data
    }
  }
`;

export const draftContextBannerMutation = graphql`
  mutation DraftContextBannerMutation(
    $input: [EditInput]!
  ) {
    meEdit(input: $input) {
      name
      draftContext {
        ...DraftContextBanner_data
      }
    }
  }
`;

export const draftContextBannerValidateDraftMutation = graphql`
  mutation DraftContextBannerValidateDraftMutation(
    $id: ID!
  ) {
    draftWorkspaceValidate(id: $id) {
      id
    }
  }
`;

interface DraftContextBannerComponentProps {
  queryRef: PreloadedQuery<DraftContextBannerQuery>;
  refetch: () => void;
}

const DraftContextBannerComponent: FunctionComponent<DraftContextBannerComponentProps> = ({ queryRef, refetch }) => {
  const { t_i18n } = useFormatter();
  const [commitExitDraft] = useApiMutation(draftContextBannerMutation);
  const [commitValidateDraft] = useApiMutation(draftContextBannerValidateDraftMutation);
  const [displayApprove, setDisplayApprove] = useState(false);
  const [approving, setApproving] = useState(false);
  const navigate = useNavigate();
  const draftContext = useDraftContext();

  const { draftWorkspace } = usePreloadedQuery<DraftContextBannerQuery>(draftContextBannerQuery, queryRef);
  if (!draftWorkspace) {
    return (<ErrorNotFound />);
  }

  const { name, processingCount } = useFragment<DraftContextBanner_data$key>(draftContextBannerFragment, draftWorkspace);
  const currentlyProcessing = processingCount > 0;

  const handleExitDraft = () => {
    commitExitDraft({
      variables: {
        input: { key: 'draft_context', value: '' },
      },
      onCompleted: () => {
        navigate('/');
      },
    });
  };

  const handleValidateDraft = () => {
    setApproving(true);
    if (draftContext) {
      commitValidateDraft({
        variables: {
          id: draftContext.id,
        },
        onCompleted: () => {
          commitExitDraft({
            variables: {
              input: { key: 'draft_context', value: '' },
            },
            onCompleted: () => {
              setApproving(false);
              MESSAGING$.notifySuccess('Draft validation in progress');
              navigate('/');
            },
          });
        },
      });
    }
  };

  useEffect(() => {
    // Refresh
    const subscription = interval$.subscribe(() => {
      refetch();
    });
    return function cleanup() {
      subscription.unsubscribe();
    };
  }, []);

  return (
    <div style={{ padding: '0 12px', flex: 1 }}>
      <div style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
        <div style={{ padding: '0 12px' }}>
          <DraftProcessingStatus/>
        </div>
        <div style={{ padding: '0 12px', flex: 1 }}>
          <DraftBlock body={truncate(name, 40)}/>
        </div>
        <div>
          <Button
            color="primary"
            variant="outlined"
            style={{ width: '100%' }}
            onClick={handleExitDraft}
          >
            {t_i18n('Exit draft')}
          </Button>
        </div>
        <div style={{ padding: '0 12px' }}>
          <Button
            variant="contained"
            color="primary"
            style={{ width: '100%' }}
            onClick={() => setDisplayApprove(true)}
          >
            {t_i18n('Approve draft')}
          </Button>
          <Dialog
            open={displayApprove}
            PaperProps={{ elevation: 1 }}
            keepMounted={true}
            TransitionComponent={Transition}
            onClose={() => setDisplayApprove(false)}
          >
            <DialogTitle>
              {t_i18n('Are you sure?')}
            </DialogTitle>
            <DialogContent>
              <DialogContentText>
                {t_i18n('Do you want to approve this draft and send it to ingestion?')}
                {currentlyProcessing && (
                <Alert style={{ marginTop: 10 }} severity={'warning'}>
                  <AlertTitle>{t_i18n('Ongoing processes')}</AlertTitle>
                  {t_i18n('There are processes still running that could impact the data of the draft. '
                      + 'By approving the draft now, the remaining changes that would have been applied by those processes will be ignored.')}
                </Alert>)}
              </DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDisplayApprove(false)} disabled={approving}>
                {t_i18n('Cancel')}
              </Button>
              <Button color="secondary" onClick={handleValidateDraft} disabled={approving}>
                {t_i18n('Approve')}
              </Button>
            </DialogActions>
          </Dialog>
        </div>
      </div>
    </div>
  );
};

const DraftContextBanner = () => {
  const draftContext = useDraftContext();
  const [queryRef, loadQuery] = useQueryLoader<DraftContextBannerQuery>(draftContextBannerQuery);

  if (!draftContext) {
    return null;
  }

  useEffect(() => {
    loadQuery({ id: draftContext.id }, { fetchPolicy: 'store-and-network' });
  }, []);

  const refetch = React.useCallback(() => {
    loadQuery({ id: draftContext.id }, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <DraftContextBannerComponent queryRef={queryRef} refetch={refetch} />
        </Suspense>
      )}
    </>
  );
};

export default DraftContextBanner;
