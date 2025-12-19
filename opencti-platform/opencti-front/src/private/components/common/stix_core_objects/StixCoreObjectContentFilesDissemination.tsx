import React, { FunctionComponent, useState } from 'react';
import Button from '@common/button/Button';
import { Box } from '@mui/material';
import CircularProgress from '@mui/material/CircularProgress';
import { graphql } from 'react-relay';
import { Field, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { useTheme } from '@mui/styles';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import DisseminationListField from '../../../../components/fields/DisseminationListField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';

interface StixCoreObjectContentFilesDisseminationProps {
  entityId: string;
  fileId: string;
  fileName: string;
  fileType: string;
  onClose: () => void;
}

interface DisseminationInput {
  disseminationListId: string;
  emailObject: string;
  emailBody: string;
}

export const DisseminationListSendInputMutation = graphql`
    mutation StixCoreObjectContentFilesDisseminationMutation(
        $id: ID!
        $input: DisseminationListSendInput!
    ) {
        disseminationListSend(id: $id, input: $input)
    }
`;

const StixCoreObjectContentFilesDissemination: FunctionComponent<StixCoreObjectContentFilesDisseminationProps> = ({
  fileId,
  entityId,
  fileName,
  fileType,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [useFileContent, setUseFileContent] = useState(false);
  const [useOctiTemplate, setUseOctiTemplate] = useState(true);

  const basicShape = {
    disseminationListId: Yup.string().required(t_i18n('This field is required')),
    emailObject: Yup.string().required(t_i18n('This field is required')),
    emailBody: useFileContent ? Yup.string() : Yup.string().required(t_i18n('This field is required')),
  };
  const validator = Yup.object().shape(basicShape);
  const [commitMutation, inProgress] = useApiMutation(
    DisseminationListSendInputMutation,
    undefined,
    {
      successMessage: t_i18n('Email sent successfully'),
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
        id: values.disseminationListId,
        input: {
          entity_id: entityId,
          use_octi_template: useOctiTemplate,
          email_object: values.emailObject,
          email_body: emailBodyFormatted,
          email_attachment_ids: useFileContent ? [] : [fileId],
          html_to_body_file_id: useFileContent ? fileId : undefined,
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
          <FormControlLabel
            style={{ marginBottom: theme.spacing(2) }}
            control={(
              <Switch
                checked={useOctiTemplate}
                onChange={() => setUseOctiTemplate(!useOctiTemplate)}
                color="primary"
              />
            )}
            label={t_i18n('Use OpenCTI template')}
          />
          <DisseminationListField />
          <Field
            component={TextField}
            label={t_i18n('Email subject')}
            name="emailObject"
            fullWidth
            required
            style={fieldSpacingContainerStyle}
          />
          {fileType === 'text/html' && (
            <FormControlLabel
              style={{
                marginTop: theme.spacing(2),
              }}
              control={(
                <Switch
                  checked={useFileContent}
                  onChange={() => setUseFileContent(!useFileContent)}
                  color="primary"
                />
              )}
              label={t_i18n('Use file content as email body')}
            />
          )}
          {!useFileContent && (
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
          )}
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
            gap: theme.spacing(2),
            display: 'flex',
            justifyContent: 'right',
            alignItems: 'center',
          }}
          >
            { inProgress && (
              <CircularProgress size={30} thickness={2} />
            )}
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting || inProgress}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting || inProgress}
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
