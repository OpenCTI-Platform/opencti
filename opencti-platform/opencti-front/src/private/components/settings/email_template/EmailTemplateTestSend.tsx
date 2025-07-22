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
import CreatorField from '@components/common/form/CreatorField';
import { FormikConfig } from 'formik/dist/types';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const emailTemplateTestSendMutation = graphql`
    mutation EmailTemplateTestSendMutation($id: ID!, $userId: ID!) {
        emailTemplateTestSend(id: $id, userId: $userId)
    }
`;

interface EmailTemplateTestSendFormInputs {
  user_id: { label: string; value: string }
}
interface EmailTemplateTestSendProps {
  templateId: string;
}

const EmailTemplateTestSend = ({ templateId }: EmailTemplateTestSendProps) => {
  const { t_i18n } = useFormatter();
  const [commitSendTestEmailMutation] = useApiMutation(emailTemplateTestSendMutation);
  const [isEmailAddressSelectionShown, setIsEmailAddressSelectionShown] = useState(false);

  const submitSendEmail: FormikConfig<EmailTemplateTestSendFormInputs>['onSubmit'] = (values, { setSubmitting }) => {
    commitSendTestEmailMutation({
      variables: {
        id: templateId,
        userId: values.user_id.value,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Email sent to user'));
        setSubmitting(false);
        setIsEmailAddressSelectionShown(false);
      },
      onError: (error: Error) => {
        handleError(error);
        setSubmitting(false);
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
        {({ setFieldValue, submitForm, handleReset, isSubmitting }) => (
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={isEmailAddressSelectionShown}
            onClose={() => handleReset()}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Send a test email to selected user')}</DialogTitle>
            <DialogContent style={{ overflowY: 'hidden' }}>
              <Form>
                <CreatorField
                  name="user_id"
                  label={t_i18n('User to send test email to')}
                  containerStyle={fieldSpacingContainerStyle}
                  onChange={setFieldValue}
                />
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
