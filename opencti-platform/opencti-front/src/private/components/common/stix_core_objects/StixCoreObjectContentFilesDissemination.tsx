import React, { FunctionComponent, useState } from 'react';
import { Box, Button } from '@mui/material';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Field, Formik } from 'formik';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import Select from '@mui/material/Select';
import { StixCoreObjectContentFilesDisseminationQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectContentFilesDisseminationQuery.graphql';
import MenuItem from '@mui/material/MenuItem';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { useFormatter } from '../../../../components/i18n';
import { handleErrorInForm } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import SelectField from "../../../../components/fields/SelectField";

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

export const stixCoreObjectContentFilesDisseminationQuery = graphql`
  query StixCoreObjectContentFilesDisseminationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DisseminationListOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    disseminationListsNames(
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

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
  const [selectedListId, setSelectedListId] = useState('');
  const { disseminationListsNames } = useLazyLoadQuery<StixCoreObjectContentFilesDisseminationQuery>(
    stixCoreObjectContentFilesDisseminationQuery,
    { search: '', count: 10 },
  );

  const basicShape = {
    disseminationList: Yup.string().required(t_i18n('This field is required')),
    emailObject: Yup.string().required(t_i18n('This field is required')),
    emailBody: Yup.string().required(t_i18n('This field is required')),
  };
  const validator = Yup.object().shape(basicShape);
  const [commitMutation] = useApiMutation(
    DisseminationListSendInputMutation,
    undefined,
    { successMessage: `${t_i18n('Email sent')}` },
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
      initialValues={{ ...initialValues, disseminationListId: selectedListId }}
      validationSchema={validator}
      validateOnChange={true}
      onSubmit={handleSubmit}
      onReset={onClose}
    >
      {({ isSubmitting, submitForm, handleReset }) => (
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <Field
            component={SelectField}
            label={t_i18n('Dissemination List')}
            name="disseminationListId"
            required
          >
            {disseminationListsNames?.edges?.map((edge) => (
              <MenuItem key={edge.node.id} value={edge.node.id}>
                {edge.node.name}
              </MenuItem>
            ))}
          </Field>
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
