import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import { Box, Button } from '@mui/material';
import { graphql } from 'react-relay';
import { Field, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { useTheme } from '@mui/styles';
import DisseminationListField from '../../../../components/fields/DisseminationListField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';

interface StixCoreObjectContentFilesDisseminationProps {
  fileId: string;
  fileName: string;
  onClose: () => void;
}

interface DisseminationInput {
  disseminationListId: string;
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
  const theme = useTheme<Theme>();

  const basicShape = {
    disseminationListId: Yup.string().required(t_i18n('This field is required')),
    emailObject: Yup.string().required(t_i18n('This field is required')),
    emailBody: Yup.string().required(t_i18n('This field is required')),
  };
  const validator = Yup.object().shape(basicShape);
  const [commitMutation] = useApiMutation(
    DisseminationListSendInputMutation,
    undefined,
    {
      successMessage: (
        <span>
          {t_i18n('The background task has been executed. You can monitor it on')}{' '}
          <Link to="/dashboard/data/processing/tasks">{t_i18n('the dedicated page')}</Link>.
        </span>
      ),
    },
  );

  const handleSubmit: FormikConfig<DisseminationInput>['onSubmit'] = async (
    values,
    { setSubmitting, resetForm, setErrors },
  ) => {
    setSubmitting(true);
    const emailBodyMarkdown = await marked(values.emailBody);
    const sanitizedEmailBody = DOMPurify.sanitize(emailBodyMarkdown);
    const emailBodyFormatted = sanitizedEmailBody.replace(/(\r\n|\n|\r)/g, '<br/>');
    commitMutation({
      variables: {
        input: {
          dissemination_list_id: values.disseminationListId,
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
    disseminationListId: '',
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
          <DisseminationListField
            label={t_i18n('Dissemination list')}
            name="disseminationListId"
            required
          />
          <Field
            component={TextField}
            label={t_i18n('Email subject')}
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
            marginTop: theme.spacing(2),
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
              style={{ marginLeft: theme.spacing(2) }}
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
