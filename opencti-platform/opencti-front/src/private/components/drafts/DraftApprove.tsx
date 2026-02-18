import { useState } from 'react';
import { graphql } from 'relay-runtime';
import { Alert, AlertTitle, DialogActions, DialogContentText, Tooltip } from '@mui/material';
import Dialog from '@common/dialog/Dialog';
import { useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import Button from '../../../components/common/button/Button';
import useUserCanApproveDraft from '../../../utils/hooks/useUserCanApproveDraft';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import Transition from '../../../components/Transition';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { MESSAGING$ } from '../../../relay/environment';
import { useNavigate } from 'react-router-dom';
import useSwitchDraft from './useSwitchDraft';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { DraftApproveFragment$key } from '@components/drafts/__generated__/DraftApproveFragment.graphql';

const draftFragment = graphql`
  fragment DraftApproveFragment on DraftWorkspace {
    id
    entity_id
    processingCount
    currentUserAccessRight
    objectsCount {
      totalCount
    }
  }
`;

const draftApproveMutation = graphql`
  mutation DraftApproveMutation($id: ID!) {
    draftWorkspaceValidate(id: $id) {
      id
    }
  }
`;

interface DraftApproveProps {
  data: DraftApproveFragment$key;
}

export const DraftApprove = ({ data }: DraftApproveProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const { exitDraft } = useSwitchDraft();
  const canDeleteKnowledge = useUserCanApproveDraft();
  const [commitApprove, approving] = useApiMutation(draftApproveMutation);
  const [displayApprove, setDisplayApprove] = useState(false);

  const {
    id,
    entity_id,
    currentUserAccessRight,
    objectsCount,
    processingCount,
  } = useFragment(draftFragment, data);

  const currentAccessRight = useGetCurrentUserAccessRight(currentUserAccessRight);
  const canApprove = canDeleteKnowledge && currentAccessRight.canEdit;

  const approveDraft = () => {
    if (draftContext) {
      commitApprove({
        variables: { id },
        onCompleted: () => {
          exitDraft({
            onCompleted: () => {
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

  let button = (
    <Button
      onClick={() => setDisplayApprove(true)}
      disabled={objectsCount.totalCount < 1}
    >
      {t_i18n('Approve draft')}
    </Button>
  );
  if (!canApprove) {
    button = (
      <Tooltip title={t_i18n('You do not have the access rights to approve a draft')}>
        <span>
          <Button disabled>
            {t_i18n('Approve draft')}
          </Button>
        </span>
      </Tooltip>
    );
  }

  return (
    <>
      {button}

      <Dialog
        open={displayApprove}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={() => setDisplayApprove(false)}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to approve this draft and send it to ingestion?')}
          {processingCount > 0 && (
            <Alert sx={{ marginTop: 1 }} severity="warning">
              <AlertTitle>{t_i18n('Ongoing processes')}</AlertTitle>
              {t_i18n('There are processes still running that could impact the data of the draft. '
                + 'By approving the draft now, the remaining changes that would have been applied by those processes will be ignored.')}
            </Alert>
          )}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setDisplayApprove(false)}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={approveDraft}
            disabled={approving}
          >
            {t_i18n('Approve')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default DraftApprove;
