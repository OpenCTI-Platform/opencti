import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import { graphql } from 'react-relay';
import { Field, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { marked } from 'marked';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

interface StixCoreObjectContentFilesDisseminationProps {
  fileId: string;
  fileName: string;
  onClose: () => void;
}

interface DisseminationInput {
  emailAddress: string;
  emailObject: string;
  emailBody: string;
}

export const DisseminationListSendInputMutation = graphql`
    mutation StixCoreObjectContentFilesDisseminationMutation(
        $input: DisseminationListSendInput!
    ) {
        disseminationListSend(input: $input)
    }
`;

const StixCoreObjectContentFilesDissemination: FunctionComponent<StixCoreObjectContentFilesDisseminationProps> = ({
  fileId,
  fileName,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const basicShape = {
    emailAddress: Yup.string().required(t_i18n('This field is required')),
    emailObject: Yup.string().required(t_i18n('This field is required')),
    emailBody: Yup.string().required(t_i18n('This field is required')),
  };
  const validator = Yup.object().shape(basicShape);
  const [commitMutation] = useApiMutation(
    DisseminationListSendInputMutation,
    undefined,
    { successMessage: `${t_i18n('Email sent')}` },
  );

  const handleSubmit: FormikConfig<DisseminationInput>['onSubmit'] = (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    setSubmitting(true);
    const emailBodyFormatted = marked(values.emailBody);
    commitMutation({
      variables: {
        input: {
          email_address: values.emailAddress,
          email_object: values.emailObject,
          email_body: emailBodyFormatted,
          email_attached_file_id: fileId,
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        onClose();
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };
  const initialValues = {
    emailAddress: '',
    emailObject: '',
    emailBody: '',
  };
  return (
    <Formik
      initialValues={initialValues}
      validationSchema={validator}
      validateOnChange={true}
      onSubmit={handleSubmit}
      onReset={onClose}
    >
      {({ isSubmitting, submitForm, handleReset }) => (
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <Field
            component={TextField}
            label={t_i18n('Email address')}
            name="emailAddress"
            type="email"
            fullWidth
            required
          />
          <Field
            component={TextField}
            label={t_i18n('Email object')}
            name="emailObject"
            fullWidth
            required
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={MarkdownField}
            label={t_i18n('Email body')}
            name="emailBody"
            multiline
            rows="4"
            fullWidth
            required
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={TextField}
            label={t_i18n('File')}
            name="file"
            fullWidth
            value={fileName}
            disabled
            style={fieldSpacingContainerStyle}
          />
          <div style={{
            marginTop: 20,
            textAlign: 'right',
          }}
          >
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: 16 }}
            >
              {t_i18n('Send')}
            </Button>
          </div>
        </Box>
      )}
    </Formik>
  );
};

export default StixCoreObjectContentFilesDissemination;
