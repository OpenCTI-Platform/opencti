import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import TextField from '@mui/material/TextField';
import { DialogActions } from '@mui/material';
import Dialog from '@common/dialog/Dialog';
import Button from '@common/button/Button';
import { useFormatter } from 'src/components/i18n';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { MESSAGING$ } from 'src/relay/environment';

const smtpConfigurationTestMutation = graphql`
  mutation SmtpTestDialogMutation($email: String!) {
    smtpConfigurationTest(email: $email)
  }
`;

interface SmtpTestDialogProps {
  open: boolean;
  onClose: () => void;
}

const SmtpTestDialog: FunctionComponent<SmtpTestDialogProps> = ({ open, onClose }) => {
  const { t_i18n } = useFormatter();
  const [email, setEmail] = useState('');
  const [commitTest, isTesting] = useApiMutation(smtpConfigurationTestMutation);

  const handleClose = () => {
    setEmail('');
    onClose();
  };

  const handleSend = () => {
    commitTest({
      variables: { email },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Email sent, please check your inbox'));
        handleClose();
      },
    });
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      title={t_i18n('Test email')}
    >
      <Alert severity="warning" variant="outlined" style={{ marginBottom: 16 }}>
        {t_i18n('This test only confirms the SMTP server accepted the message. It does not guarantee that the email was actually delivered.')}
      </Alert>
      <TextField
        label={t_i18n('Email address')}
        fullWidth={true}
        type="email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
      />
      <DialogActions>
        <Button variant="secondary" onClick={handleClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button disabled={isTesting || !email} onClick={handleSend}>
          {t_i18n('Send')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default SmtpTestDialog;
