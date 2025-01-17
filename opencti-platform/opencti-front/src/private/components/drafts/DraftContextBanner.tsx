import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import DraftBlock from '@components/common/draft/DraftBlock';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { truncate } from '../../../utils/String';
import { MESSAGING$ } from '../../../relay/environment';
import Transition from '../../../components/Transition';

export const draftContextBannerMutation = graphql`
  mutation DraftContextBannerMutation(
    $input: [EditInput]!
  ) {
    meEdit(input: $input) {
      name
      draftContext {
        id
        name
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

const DraftContextBanner = () => {
  const { t_i18n } = useFormatter();
  const [commitExitDraft] = useApiMutation(draftContextBannerMutation);
  const [commitValidateDraft] = useApiMutation(draftContextBannerValidateDraftMutation);
  const [displayApprove, setDisplayApprove] = useState(false);
  const [approving, setApproving] = useState(false);
  const navigate = useNavigate();
  const draftContext = useDraftContext();
  const currentDraftContextName = draftContext?.name ?? '';
  const currentDraftContextId = draftContext?.id ?? '';

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
          setApproving(false);
          MESSAGING$.notifySuccess('Draft validation in progress');
          navigate('/');
        },
      });
    }
  };

  const navigateToDraft = () => {
    navigate(`/dashboard/drafts/${currentDraftContextId}`);
  };

  return (
    <div style={{ padding: '0 12px', flex: 1 }}>
      <div style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
        <div style={{ padding: '0 12px', flex: 1 }}>
          <DraftBlock body={truncate(currentDraftContextName, 40)}/>
        </div>
        <div>
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
            <DialogContent>
              <DialogContentText>
                {t_i18n('Do you want to approve this draft and send it to ingestion?')}
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
        <div style={{ padding: '0 12px' }}>
          <Button
            variant="contained"
            color="secondary"
            style={{ width: '100%' }}
            onClick={navigateToDraft}
          >
            {t_i18n('View draft')}
          </Button>
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
      </div>
    </div>
  );
};

export default DraftContextBanner;
