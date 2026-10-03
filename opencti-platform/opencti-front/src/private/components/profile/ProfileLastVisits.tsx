import React, { useState } from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import Card from '../../../components/common/card/Card';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { ProfileLastVisitsPurgeMutation } from './__generated__/ProfileLastVisitsPurgeMutation.graphql';

const profileLastVisitsPurgeMutation = graphql`
  mutation ProfileLastVisitsPurgeMutation {
    userVisitsPurge
  }
`;

/**
 * The platform remembers when the user last opened each entity to show what is new since then.
 * The user can purge these markers at any time.
 */
const ProfileLastVisits: React.FC = () => {
  const { t_i18n } = useFormatter();
  const [displayConfirmation, setDisplayConfirmation] = useState(false);
  const [commitPurge, purging] = useApiMutation<ProfileLastVisitsPurgeMutation>(
    profileLastVisitsPurgeMutation,
    undefined,
    { successMessage: t_i18n('Your last visit markers have been purged') },
  );
  return (
    <>
      <Card title={t_i18n('Last visit markers')} sx={{ marginBottom: 3 }}>
        <Alert severity="info" variant="outlined">
          {t_i18n('The platform remembers when you last opened each entity to highlight what is new since your last visit. These markers are only visible to you and expire automatically.')}
        </Alert>
        <div style={{ display: 'flex', justifyContent: 'end', marginTop: 16 }}>
          <Button onClick={() => setDisplayConfirmation(true)} disabled={purging} data-testid="purge-last-visits">
            {t_i18n('Purge my last visit markers')}
          </Button>
        </div>
      </Card>
      <Dialog
        open={displayConfirmation}
        onClose={() => setDisplayConfirmation(false)}
        title={t_i18n('Purge my last visit markers')}
      >
        <Alert icon={false} severity="warning" variant="outlined" sx={{ color: 'text.primary' }}>
          <AlertTitle style={{ marginBottom: 0, fontWeight: 400 }}>
            {t_i18n('Every entity will be considered as never visited. Are you sure?')}
          </AlertTitle>
        </Alert>
        <DialogActions>
          <Button variant="secondary" onClick={() => setDisplayConfirmation(false)}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => {
              commitPurge({ variables: {}, onCompleted: () => setDisplayConfirmation(false) });
            }}
          >
            {t_i18n('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default ProfileLastVisits;
