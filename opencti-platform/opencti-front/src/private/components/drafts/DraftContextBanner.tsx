import DraftBlock from '@components/common/draft/DraftBlock';
import FormAuthorizedMembersDialog from '@components/common/form/FormAuthorizedMembersDialog';
import { DraftContextBanner_data$key } from '@components/drafts/__generated__/DraftContextBanner_data.graphql';
import { DraftContextBannerQuery } from '@components/drafts/__generated__/DraftContextBannerQuery.graphql';
import DraftProcessingStatus from '@components/drafts/DraftProcessingStatus';
import { LockOutlined } from '@mui/icons-material';
import { AlertTitle, IconButton, Tooltip } from '@mui/material';
import Alert from '@mui/material/Alert';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogTitle from '@mui/material/DialogTitle';
import React, { FunctionComponent, Suspense, useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery, useQueryLoader } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { interval } from 'rxjs';
import ErrorNotFound from '../../../components/ErrorNotFound';
import { useFormatter } from '../../../components/i18n';
import Transition from '../../../components/Transition';
import { MESSAGING$ } from '../../../relay/environment';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { truncate } from '../../../utils/String';
import { TEN_SECONDS } from '../../../utils/Time';
import { useGetCurrentUserAccessRight, authorizedMembersToOptions } from '../../../utils/authorizedMembers';
import useUserCanApproveDraft from '../../../utils/hooks/useUserCanApproveDraft';

const interval$ = interval(TEN_SECONDS * 3);

const draftContextBannerFragment = graphql`
  fragment DraftContextBanner_data on DraftWorkspace {
    id
    name
    entity_id
    draft_status
    processingCount
    objectsCount {
      totalCount
    }
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
    creators {
      id
      name
      entity_type
    }
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

export const draftContextBannerDraftEditAuthorizedMembersMutation = graphql`
  mutation DraftContextBannerDraftEditAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    draftWorkspaceEditAuthorizedMembers(id: $id, input: $input) {
      id
      ...DraftRootFragment
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
  const [displayAuthorizeMembersDialog, setDisplayAuthorizeMembersDialog] = useState(false);
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const canDeleteKnowledge = useUserCanApproveDraft();
  const currentAccessRight = useGetCurrentUserAccessRight(draftContext?.currentUserAccessRight);

  const { draftWorkspace } = usePreloadedQuery<DraftContextBannerQuery>(draftContextBannerQuery, queryRef);
  if (!draftWorkspace) {
    return (<ErrorNotFound />);
  }

  const {
    id,
    name,
    processingCount,
    objectsCount,
    entity_id,
    creators,
    authorizedMembers,
  } = useFragment<DraftContextBanner_data$key>(draftContextBannerFragment, draftWorkspace);
  const currentlyProcessing = processingCount > 0;
  const handleExitDraft = () => {
    commitExitDraft({
      variables: {
        input: { key: 'draft_context', value: '' },
      },
      onCompleted: () => {
        if (entity_id) {
          navigate(`/dashboard/id/${entity_id}`);
        } else {
          navigate('/dashboard/data/import/draft');
        }
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
              if (entity_id) {
                navigate(`/dashboard/id/${entity_id}`);
              } else {
                navigate('/dashboard/data/import/draft');
              }
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
          {currentAccessRight.canManage && (
            <Tooltip title={t_i18n('Authorized members')}>
              <IconButton
                onClick={() => {
                  setDisplayAuthorizeMembersDialog(true);
                }}
                color="primary"
              >
                <LockOutlined />
              </IconButton>
            </Tooltip>
          )}
          {displayAuthorizeMembersDialog && (
            <FormAuthorizedMembersDialog
              id={id}
              mutation={draftContextBannerDraftEditAuthorizedMembersMutation}
              authorizedMembers={authorizedMembersToOptions(authorizedMembers)}
              open={displayAuthorizeMembersDialog}
              handleClose={() => setDisplayAuthorizeMembersDialog(false)}
              owner={creators?.[0]}
              canDeactivate
            />
          )}
        </div>
        <div style={{ padding: '0 12px' }}>
          <DraftProcessingStatus forceRefetch={refetch} />
        </div>
        <div style={{ padding: '0 12px', flex: 1 }}>
          <DraftBlock body={truncate(name, 40)} />
        </div>
        <div>
          <Button
            variant="secondary"
            style={{ width: '100%' }}
            onClick={handleExitDraft}
          >
            {t_i18n('Exit draft')}
          </Button>
        </div>

        <div style={{ padding: '0 12px' }}>
          <Tooltip title={(!canDeleteKnowledge || !currentAccessRight.canEdit) ? t_i18n('You do not have the access rights to approve a draft') : ''}>
            <span>
              <Button
                style={{ width: '100%' }}
                onClick={() => setDisplayApprove(true)}
                disabled={objectsCount.totalCount < 1 || !canDeleteKnowledge || !currentAccessRight.canEdit}
              >
                {t_i18n('Approve draft')}
              </Button>
            </span>
          </Tooltip>
          <Dialog
            open={displayApprove}
            slotProps={{ paper: { elevation: 1 } }}
            keepMounted={true}
            slots={{ transition: Transition }}
            onClose={() => setDisplayApprove(false)}
          >
            <DialogTitle>
              {t_i18n('Are you sure?')}
            </DialogTitle>
            <DialogContent>
              <DialogContentText>
                {t_i18n('Do you want to approve this draft and send it to ingestion?')}
                {currentlyProcessing && (
                  <Alert style={{ marginTop: 10 }} severity="warning">
                    <AlertTitle>{t_i18n('Ongoing processes')}</AlertTitle>
                    {t_i18n('There are processes still running that could impact the data of the draft. '
                      + 'By approving the draft now, the remaining changes that would have been applied by those processes will be ignored.')}
                  </Alert>
                )}
              </DialogContentText>
            </DialogContent>
            <DialogActions>
              <Button variant="secondary" onClick={() => setDisplayApprove(false)} disabled={approving}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={handleValidateDraft} disabled={approving}>
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

  const refetch = React.useCallback(() => {
    loadQuery({ id: draftContext.id }, { fetchPolicy: 'store-and-network' });
  }, [queryRef, draftContext]);

  useEffect(() => {
    refetch();
  }, [draftContext.id]);

  return (
    <>
      {queryRef && (
        <Suspense>
          <DraftContextBannerComponent queryRef={queryRef} refetch={refetch} />
        </Suspense>
      )}
    </>
  );
};

export default DraftContextBanner;
