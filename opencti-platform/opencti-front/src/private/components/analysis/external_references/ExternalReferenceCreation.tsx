import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import * as R from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { SimpleFileUpload } from 'formik-mui';
import { Add, Close } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { FormikConfig } from 'formik/dist/types';
import {
  commitMutation,
  handleErrorInForm,
} from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { insertNode } from '../../../../utils/store';
import { ExternalReferencesLinesPaginationQuery$variables } from './__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { Theme } from '../../../../components/Theme';
import {
  ExternalReferenceAddInput,
  ExternalReferenceCreationMutation$data,
} from './__generated__/ExternalReferenceCreationMutation.graphql';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  createButtonContextual: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 3000,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

export const externalReferenceCreationMutation = graphql`
  mutation ExternalReferenceCreationMutation(
    $input: ExternalReferenceAddInput!
  ) {
    externalReferenceAdd(input: $input) {
      id
      source_name
      description
      url
      external_id
      created
      fileId
    }
  }
`;

const externalReferenceValidation = (t: (value: string) => string) => Yup.object().shape({
  source_name: Yup.string().required(t('This field is required')),
  external_id: Yup.string().nullable(),
  url: Yup.string().url(t('The value must be an URL')).nullable(),
  description: Yup.string().nullable(),
  file: Yup.object().nullable(),
});

interface ExternalReferenceCreationProps {
  paginationOptions?: ExternalReferencesLinesPaginationQuery$variables;
  display?: boolean;
  contextual?: boolean;
  inputValue?: string;
  onCreate?: (
    externalReference: ExternalReferenceAddInput | null,
    onlyCreate: boolean
  ) => void;
  openContextual: boolean;
  handleCloseContextual?: () => void;
  creationCallback?: (data: ExternalReferenceCreationMutation$data) => void;
  dryrun?: boolean;
}

const ExternalReferenceCreation: FunctionComponent<
ExternalReferenceCreationProps
> = ({
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
  const classes = useStyles();
  const { t } = useFormatter();

  const [open, setOpen] = useState(false);

  const handleOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

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
    commitMutation({
      mutation: externalReferenceCreationMutation,
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
      setSubmitting,
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
    commitMutation({
      mutation: externalReferenceCreationMutation,
      variables: {
        input: finalValues,
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: (response: ExternalReferenceCreationMutation$data) => {
        setSubmitting(false);
        resetForm();
        if (creationCallback && handleCloseContextual) {
          creationCallback(response);
          handleCloseContextual();
        }
      },
      updater: undefined,
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

  const renderClassic = () => {
    return (
      <div>
        <Fab
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}
        >
          <Add />
        </Fab>
        <Drawer
          open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={handleClose}
              size="large"
              color="primary"
            >
              <Close fontSize="small" color="primary" />
            </IconButton>
            <Typography variant="h6">
              {t('Create an external reference')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                source_name: '',
                external_id: '',
                url: '',
                description: '',
                file: '',
              }}
              validationSchema={externalReferenceValidation(t)}
              onSubmit={onSubmit}
              onReset={onResetClassic}
            >
              {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="source_name"
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="external_id"
                    id={'external_id'}
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="url"
                    label={t('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  {!dryrun && (
                    <Field
                      component={SimpleFileUpload}
                      name="file"
                      label={t('Associated file')}
                      FormControlProps={{ style: fieldSpacingContainerStyle }}
                      InputLabelProps={{ fullWidth: true, variant: 'standard' }}
                      InputProps={{
                        classes: { fullWidth: true, variant: 'standard' },
                        onChange: (event: React.ChangeEvent<HTMLInputElement>) => {
                          const fileName = event.target.value.split('\\').pop();
                          const externalIdValue = (document.getElementById('external_id') as HTMLInputElement).value;
                          if (!externalIdValue && fileName) {
                            setFieldValue('file', event.currentTarget.files?.[0]);
                            setFieldValue('external_id', fileName);
                          }
                        },
                      }}
                      fullWidth={true}
                    />
                  )}
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
                    fullWidth={true}
                    multiline={true}
                    rows="4"
                    style={{ marginTop: 20 }}
                  />
                  <div className={classes.buttons}>
                    <Button
                      variant="contained"
                      onClick={handleReset}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Cancel')}
                    </Button>
                    <Button
                      variant="contained"
                      color="secondary"
                      onClick={submitForm}
                      disabled={isSubmitting}
                      classes={{ root: classes.button }}
                    >
                      {t('Create')}
                    </Button>
                  </div>
                </Form>
              )}
            </Formik>
          </div>
        </Drawer>
      </div>
    );
  };

  const renderContextual = () => {
    return (
      <div style={{ display: display ? 'block' : 'none' }}>
        {!handleCloseContextual && (
          <Fab
            onClick={handleOpen}
            color="secondary"
            aria-label="Add"
            className={classes.createButtonContextual}
          >
            <Add />
          </Fab>
        )}
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={!handleCloseContextual ? open : openContextual}
          onClose={!handleCloseContextual ? handleClose : handleCloseContextual}
        >
          <Formik
            enableReinitialize={true}
            onSubmit={!handleCloseContextual ? onSubmit : onSubmitContextual}
            initialValues={{
              source_name: inputValue,
              external_id: '',
              url: '',
              description: '',
              file: '',
            }}
            validationSchema={externalReferenceValidation(t)}
            onReset={onResetContextual}
          >
            {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
              <Form>
                <DialogTitle>{t('Create an external reference')}</DialogTitle>
                <DialogContent>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="source_name"
                    label={t('Source name')}
                    fullWidth={true}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="external_id"
                    id={'external_id'}
                    label={t('External ID')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="url"
                    label={t('URL')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                  {!dryrun && (
                    <Field
                      component={SimpleFileUpload}
                      name="file"
                      label={t('Associated file')}
                      FormControlProps={{ style: fieldSpacingContainerStyle }}
                      InputLabelProps={{ fullWidth: true, variant: 'standard' }}
                      InputProps={{ classes: { fullWidth: true, variant: 'standard' },
                        onChange: (event: React.ChangeEvent<HTMLInputElement>) => {
                          const fileName = event.target.value.split('\\').pop();
                          const externalIdValue = (document.getElementById('external_id') as HTMLInputElement).value;
                          if (!externalIdValue && fileName) {
                            setFieldValue('file', event.currentTarget.files?.[0]);
                            setFieldValue('external_id', fileName);
                          }
                        },
                      }}
                      fullWidth={true}
                    />
                  )}
                  <Field
                    component={MarkDownField}
                    name="description"
                    label={t('Description')}
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
                    {t('Cancel')}
                  </Button>
                  <Button
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                  >
                    {t('Create')}
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
