import React, { useState } from 'react';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { SendOutline } from 'mdi-material-ui';
import Tooltip from '@mui/material/Tooltip';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';

const emailTemplateTestSendMutation = graphql`
    mutation EmailTemplateTestSendMutation($id: ID!) {
        emailTemplateTestSend(id: $id)
    }
`;

interface EmailTemplateTestSendProps {
  templateId: string;
}

const EmailTemplateTestSend = ({ templateId }: EmailTemplateTestSendProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const [commitSendTestEmailMutation] = useApiMutation(emailTemplateTestSendMutation);
  const [sending, setSending] = useState(false);

  const submitSendEmail = () => {
    setSending(true);
    commitSendTestEmailMutation({
      variables: {
        id: templateId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(`${t_i18n('Test email successfully sent to you.')} (${me.user_email})`);
        setSending(false);
      },
      onError: (error: Error) => {
        handleError(error);
        setSending(false);
      },
    });
  };

  return (
    <>
      <ToggleButton
        disabled={sending}
        onClick={submitSendEmail}
        value="sendEmail"
        size="small"
      >
        <Tooltip title={t_i18n('Send test email')}>
          <SendOutline fontSize="small" color={sending ? 'disabled' : 'primary'} />
        </Tooltip>
      </ToggleButton>
    </>
  );
};

export default EmailTemplateTestSend;
