import React, { useState } from 'react';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { SendOutline } from 'mdi-material-ui';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import { Form, Formik } from 'formik';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import EmailTemplateField, { EmailTemplateFieldOption } from '@components/common/form/EmailTemplateField';
import { FormikConfig } from 'formik/dist/types';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';

const userEmailSendMutation = graphql`
  mutation UserEmailSendMutation($input: SendUserMailInput!) {
    sendUserMail(input: $input)
  }
`;

interface UserEmailFormInputs {
  emailTemplate: EmailTemplateFieldOption
}
interface UserEmailSendProps {
  userId: string;
}
const UserEmailSend = ({ userId }: UserEmailSendProps) => {
  const { t_i18n } = useFormatter();
  const [commitSendEmailMutation] = useApiMutation(userEmailSendMutation);
  const [isEmailTemplateSelectionShown, setIsEmailTemplateSelectionShown] = useState(false);

  const submitSendEmail: FormikConfig<UserEmailFormInputs>['onSubmit'] = (values, { setSubmitting }) => {
    const input = {
      target_user_id: userId,
      email_template_id: values.emailTemplate.value.id,
      email_object: '',
    };
    commitSendEmailMutation({
      variables: {
        input,
      },
      onCompleted: () => {
        setIsEmailTemplateSelectionShown(false);
        setSubmitting(false);
      },
      onError: (error: Error) => {
        handleError(error);
        setIsEmailTemplateSelectionShown(false);
        setSubmitting(false);
      },
    });
  };

  const initialValues: UserEmailFormInputs = { emailTemplate: { value: { id: '', name: '' }, label: '' } };
  return (
    <>
      <EETooltip title={t_i18n('Send email')}>
        <ToggleButton
          onClick={() => setIsEmailTemplateSelectionShown(true)}
          value="sendEmail"
          size="small"
        >
          <SendOutline fontSize="small" color="primary" />
        </ToggleButton>
      </EETooltip>
      <Formik
        initialValues={initialValues}
        onSubmit={submitSendEmail}
        onReset={() => setIsEmailTemplateSelectionShown(false)}
      >
        {({ setFieldValue, submitForm, handleReset, isSubmitting }) => (
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={isEmailTemplateSelectionShown}
            onClose={() => handleReset()}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Send email with selected email template')}</DialogTitle>
            <DialogContent style={{ overflowY: 'hidden' }}>
              <Form>
                <EmailTemplateField
                  name="emailTemplate"
                  label={t_i18n('Email template')}
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

export default UserEmailSend;
