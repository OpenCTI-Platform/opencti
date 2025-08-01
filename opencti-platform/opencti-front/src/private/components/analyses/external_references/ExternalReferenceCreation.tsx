import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import Drawer, { DrawerControlledDialProps } from '@components/common/drawer/Drawer';
import useApiMutation from 'src/utils/hooks/useApiMutation';
import { useTheme } from '@mui/material/styles';
import { ExternalReferencesLinesPaginationQuery$variables } from '../__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { handleErrorInForm } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { insertNode } from '../../../../utils/store';
import { ExternalReferenceAddInput, ExternalReferenceCreationMutation, ExternalReferenceCreationMutation$data } from './__generated__/ExternalReferenceCreationMutation.graphql';
import CustomFileUploader from '../../common/files/CustomFileUploader';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const externalReferenceCreationMutation = graphql`
  mutation ExternalReferenceCreationMutation(
    $input: ExternalReferenceAddInput!
  ) {
    externalReferenceAdd(input: $input) {
      id
      standard_id
      entity_type
      source_name
      description
      url
      external_id
      url
      created
      fileId
      draftVersion {
          draft_id
          draft_operation
      }
      creators {
          id
          name
      }
    }
  }
`;

const externalReferenceValidation = (t: (value: string) => string) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string().nullable(),
  url: Yup.string()
    .nullable()
    .matches(
      /^https?:\/\/[^\s/$.?#].[^\s]*[^/]$/,
      t('The value must be an URL'),
    ),
  description: Yup.string().nullable(),
  file: Yup.mixed().nullable(),
});

interface ExternalReferenceCreationProps {
  paginationOptions?: ExternalReferencesLinesPaginationQuery$variables;
  display?: boolean;
  contextual?: boolean;
  inputValue?: string;
  onCreate?: (
    externalReference: ExternalReferenceAddInput | null | undefined,
    onlyCreate: boolean
  ) => void;
  openContextual: boolean;
  handleCloseContextual?: () => void;
  creationCallback?: (data: ExternalReferenceCreationMutation$data) => void;
  dryrun?: boolean;
}

const ExternalReferenceCreation: FunctionComponent<ExternalReferenceCreationProps> = ({
  contextual,
  paginationOptions,
  display,
  inputValue,
  onCreate,
  handleCloseContextual,
  creationCallback,
  openContextual,
  dryrun,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const buttonStyle = { marginLeft: theme.spacing(2) };

  const [open, setOpen] = useState(false);

  const handleClose = () => {
    setOpen(false);
  };

  const [commit] = useApiMutation<ExternalReferenceCreationMutation>(
    externalReferenceCreationMutation,
    undefined,
    { successMessage: `${t_i18n('entity_External-Reference')} ${t_i18n('successfully created')}` },
  );
  const onSubmit: FormikConfig<ExternalReferenceAddInput>['onSubmit'] = (
    values,
    { setSubmitting, setErrors, resetForm },
  ) => {
    const finalValues = values.file.length === 0 ? R.dissoc('file', values) : values;
    if (dryrun && onCreate) {
      onCreate(values, true);
      handleClose();
      return;
    }
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store: RecordSourceSelectorProxy) => insertNode(
        store,
        'Pagination_externalReferences',
        paginationOptions,
        'externalReferenceAdd',
      ),
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response: ExternalReferenceCreationMutation$data) => {
        setSubmitting(false);
        resetForm();
        handleClose();
        if (onCreate) {
          onCreate(response.externalReferenceAdd, true);
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
    });
  };

  const onSubmitContextual: FormikConfig<ExternalReferenceAddInput>['onSubmit'] = (values, { setSubmitting, setErrors, resetForm }) => {
    const finalValues = values.file.length === 0 ? R.dissoc('file', values) : values;
    if (dryrun && creationCallback && handleCloseContextual) {
      creationCallback({
        externalReferenceAdd: values,
      } as ExternalReferenceCreationMutation$data);
      handleCloseContextual();
      return;
    }
    commit({
      variables: {
        input: finalValues,
      },
      updater: (store: RecordSourceSelectorProxy) => {
        if (!creationCallback) {
          insertNode(
            store,
            'Pagination_externalReferences',
            paginationOptions,
            'externalReferenceAdd',
          );
        }
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      onCompleted: (response: ExternalReferenceCreationMutation$data) => {
        setSubmitting(false);
        resetForm();
        if (creationCallback && handleCloseContextual) {
          creationCallback(response);
          handleCloseContextual();
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
    });
  };

  const onResetClassic = () => {
    handleClose();
  };

  const onResetContextual = () => {
    if (handleCloseContextual) {
      handleCloseContextual();
    } else {
      handleClose();
    }
  };

  const isEmbeddedInExternalReferenceCreation = true;
  const CreateExternalReferenceControlledDial = (props: DrawerControlledDialProps) => (
    <CreateEntityControlledDial entityType='External-Reference' {...props} />
  );
  const renderClassic = () => {
    return (
      <Drawer
        title={t_i18n('Create an external reference')}
        controlledDial={CreateExternalReferenceControlledDial}
      >
        {({ onClose }) => (
          <Formik<ExternalReferenceAddInput>
            initialValues={{
              source_name: '',
              external_id: '',
              url: '',
              description: '',
              file: '',
            }}
            validationSchema={externalReferenceValidation(t_i18n)}
            validateOnChange={true}
            validateOnBlur={true}
            onSubmit={onSubmit}
            onReset={() => {
              onResetClassic();
              onClose();
            }}
          >
            {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
              <Form>
                <Field
                  component={TextField}
                  name="source_name"
                  label={t_i18n('Source name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  name="external_id"
                  id={'external_id'}
                  label={t_i18n('External ID')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  name="url"
                  label={t_i18n('URL')}
                  fullWidth={true}
                  style={{ marginTop: 20 }}
                />
                {!dryrun && (
                  <CustomFileUploader
                    setFieldValue={setFieldValue}
                    isEmbeddedInExternalReferenceCreation={isEmbeddedInExternalReferenceCreation}
                  />
                )}
                <Field
                  component={MarkdownField}
                  name="description"
                  label={t_i18n('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                />
                <div style={{ marginTop: 20, textAlign: 'right' }}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    style={buttonStyle}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    style={buttonStyle}
                  >
                    {t_i18n('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        )}
      </Drawer>
    );
  };

  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={handleCloseContextual ? openContextual : open}
          onClose={handleCloseContextual || handleClose}
        >
          <Formik<ExternalReferenceAddInput>
            enableReinitialize={true}
            onSubmit={!creationCallback && !handleCloseContextual ? onSubmit : onSubmitContextual}
            initialValues={{
              source_name: inputValue ?? '',
              external_id: '',
              url: '',
              description: '',
              file: '',
            }}
            validationSchema={externalReferenceValidation(t_i18n)}
            validateOnChange={true}
            validateOnBlur={true}
            onReset={onResetContextual}
          >
            {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
              <Form>
                <DialogTitle>{t_i18n('Create an external reference')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    name="source_name"
                    label={t_i18n('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    name="external_id"
                    id={'external_id'}
                    label={t_i18n('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    name="url"
                    label={t_i18n('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  {!dryrun && (
                    <CustomFileUploader
                      setFieldValue={setFieldValue}
                      isEmbeddedInExternalReferenceCreation={isEmbeddedInExternalReferenceCreation}
                    />
                  )}
                  <Field
                    component={MarkdownField}
                    name="description"
                    label={t_i18n('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20, marginBottom: 20 }}
                  />
                </DialogContent>
                <DialogActions>
                  <Button
                    onClick={handleCloseContextual || handleReset}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t_i18n('Create')}
                  </Button>
                </DialogActions>
              </Form>
            )}
          </Formik>
        </Dialog>
      </div>
    );
  };

  return contextual ? renderContextual() : renderClassic();
};

export default ExternalReferenceCreation;
