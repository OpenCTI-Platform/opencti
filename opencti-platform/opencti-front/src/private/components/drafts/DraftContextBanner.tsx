import React, { useEffect, useState } from 'react';
import {
  graphql,
  PreloadedQuery,
  useFragment,
  usePreloadedQuery,
  useQueryLoader,
  UseQueryLoaderLoadQueryOptions
} from 'react-relay';
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
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { truncate } from '../../../utils/String';
import { MESSAGING$ } from '../../../relay/environment';
import Transition from '../../../components/Transition';
import {
  ContainerMappingContent_container$data
} from "@components/common/containers/__generated__/ContainerMappingContent_container.graphql";
import {
  ContainerStixCoreObjectsSuggestedMappingQuery,
  ContainerStixCoreObjectsSuggestedMappingQuery$variables
} from "@components/common/containers/__generated__/ContainerStixCoreObjectsSuggestedMappingQuery.graphql";
import {
  containerStixCoreObjectsSuggestedMappingQuery
} from "@components/common/containers/ContainerStixCoreObjectsSuggestedMapping";

const draftContextBannerMeUserFragment = graphql`
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
  queryRef: PreloadedQuery<DraftContextBannerQuery>
  loadQuery: (variables: DraftContextBannerQuery$variables, options?: (UseQueryLoaderLoadQueryOptions | undefined)) => void
}

const DraftContextBanner = () => {
  const { t_i18n } = useFormatter();
  const [commitExitDraft] = useApiMutation(draftContextBannerMutation);
  const [commitValidateDraft] = useApiMutation(draftContextBannerValidateDraftMutation);
  const [displayApprove, setDisplayApprove] = useState(false);
  const [approving, setApproving] = useState(false);
  const navigate = useNavigate();
  const draftContext = useDraftContext();

  // const draftContextData = usePreloadedQuery<DraftContextBannerQuery>(
  //     draftContextBannerQuery,
  //     queryRef,
  // );
  const currentDraftContextName = draftContext?.name ?? '';
  const currentlyProcessing = draftContext?.processingCount && draftContext.processingCount > 0;

  // // Refetch data every 30s
  // useEffect(() => {
  //   const refetchDraftContext = () => {
  //       loadQuery(
  //           { id: draftContext?.id },
  //           { fetchPolicy: 'store-and-network' },
  //       );
  //   };
  //   const interval = setInterval(refetchDraftContext, 2000);
  //   return () => clearInterval(interval);
  // }, [loadQuery, containerData, askingSuggestion]);

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

  return (
    <div style={{ padding: '0 12px', flex: 1 }}>
      <div style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
        <div>
          <DraftProcessingStatus/>
        </div>
        <div style={{ padding: '0 12px', flex: 1 }}>
          <DraftBlock body={truncate(currentDraftContextName, 40)}/>
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

// const DraftContextBanner = () => {
//   const draftContext = useDraftContext();
//   const [queryRef, loadQuery] = useQueryLoader<DraftContextBannerQuery>(
//       draftContextBannerQuery,
//   );
//
//    useEffect(() => {
//     if (!queryRef) {
//       loadQuery(
//         { id: draftContext?.id },
//         { fetchPolicy: 'store-and-network' },
//       );
//     }
//   }, [queryRef]);
//
//   if (!queryRef) {
//     return null;
//   }
//
//   return (
//       <DraftContextBannerComponent
//           queryRef={queryRef}
//           loadQuery={loadQuery}
//       />
//   );
// };

export default DraftContextBanner;
