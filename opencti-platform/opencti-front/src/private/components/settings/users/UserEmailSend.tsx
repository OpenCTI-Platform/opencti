import React, { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import { SendOutline, Send } from 'mdi-material-ui';
import Dialog from '@mui/material/Dialog';
import { DialogTitle } from '@mui/material';
import DialogContent from '@mui/material/DialogContent';
import { Form, Formik } from 'formik';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import EmailTemplateField, { EmailTemplate, EmailTemplateFieldOption } from '@components/common/form/EmailTemplateField';
import { FormikConfig } from 'formik/dist/types';
import IconButton from '@common/button/IconButton';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { handleError, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';

const userEmailSendMutation = graphql`
  mutation UserEmailSendMutation($input: SendUserMailInput!) {
    sendUserMail(input: $input)
  }
`;

interface UserEmailFormInputs {
  emailTemplate: EmailTemplateFieldOption;
}
interface UserEmailSendProps {
  userId: string;
  outlined?: boolean;
  onSubmit?: (value: EmailTemplate) => void;
  onClose: () => void;
  isOpen?: boolean;
}
const UserEmailSend = ({ userId, isOpen, onSubmit, outlined }: UserEmailSendProps) => {
  const { t_i18n } = useFormatter();
  const [commitSendEmailMutation] = useApiMutation(userEmailSendMutation);
  const [isEmailTemplateSelectionShown, setIsEmailTemplateSelectionShown] = useState<boolean>(false);

  useEffect(() => {
    if (typeof isOpen === 'boolean') setIsEmailTemplateSelectionShown(isOpen);
  }, [isOpen]);

  const submitSendEmail: FormikConfig<UserEmailFormInputs>['onSubmit'] = (values, { setSubmitting, resetForm }) => {
    if (onSubmit) {
      onSubmit(values.emailTemplate.value);
      resetForm();
      return;
    }
    const input = {
      target_user_id: userId,
      email_template_id: values.emailTemplate.value.id,
    };
    commitSendEmailMutation({
      variables: {
        input,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Email sent to user'));
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

  const renderOutlinedButton = () => (
    <ToggleButton
      onClick={() => setIsEmailTemplateSelectionShown(true)}
      value="sendEmail"
      size="small"
    >
      <SendOutline fontSize="small" color="primary" />
    </ToggleButton>
  );

  const renderMainButton = () => (
    <IconButton
      onClick={() => setIsEmailTemplateSelectionShown(true)}
      value="sendEmail"
      size="small"
    >
      <Send fontSize="small" color="primary" />
    </IconButton>
  );

  return (
    <>
      <EETooltip title={t_i18n('Send email')}>
        {outlined
          ? renderOutlinedButton()
          : renderMainButton()
        }
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
              <Button variant="secondary">
                {t_i18n('Close')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
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
