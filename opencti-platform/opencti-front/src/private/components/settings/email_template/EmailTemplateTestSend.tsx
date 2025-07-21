import React, { useState } from 'react';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { SendOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import { Form, Formik } from 'formik';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';

const emailTemplateTestSendMutation = graphql`
    mutation EmailTemplateTestSendMutation($id: String!, $userId: String!) {
        emailTemplateTestSend(id: $id, userId: $userId)
    }
`;

interface EmailTemplateTestSendProps {
  templateId: string;
}

const EmailTemplateTestSend = ({ templateId }: EmailTemplateTestSendProps) => {
  const { t_i18n } = useFormatter();
  const [commitSendTestEmailMutation] = useApiMutation(emailTemplateTestSendMutation);
  const [isEmailAddressSelectionShown, setIsEmailAddressSelectionShown] = useState(false);

  const submitSendEmail = () => {
    commitSendTestEmailMutation({
      variables: {
        id: templateId,
        userId: '',
      },
      onCompleted: () => {
        setIsEmailAddressSelectionShown(false);
      },
      onError: (error: Error) => {
        handleError(error);
        setIsEmailAddressSelectionShown(false);
      },
    });
  };

  return (
    <>
      <ToggleButton
        onClick={() => setIsEmailAddressSelectionShown(true)}
        value="sendEmail"
        size="small"
      >
        <Tooltip title={t_i18n('Send test email')}>
          <SendOutline fontSize="small" color="primary" />
        </Tooltip>
      </ToggleButton>
      <Formik
        initialValues={{ user_id: { value: '', label: '' } }}
        onSubmit={submitSendEmail}
        onReset={() => setIsEmailAddressSelectionShown(false)}
      >
        {({ submitForm, handleReset, isSubmitting }) => (
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={isEmailAddressSelectionShown}
            onClose={() => handleReset()}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Send a test email to selected user')}</DialogTitle>
            <DialogContent style={{ overflowY: 'hidden' }}>
              <Form>
              </Form>
            </DialogContent>
            <DialogActions>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                color="secondary"
              >
                {t_i18n('Send')}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

export default EmailTemplateTestSend;
