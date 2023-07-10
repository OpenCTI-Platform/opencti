import React, { FunctionComponent, useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import TextField from '../../../../components/TextField';
import ColorPickerField from '../../../../components/ColorPickerField';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { insertNode } from '../../../../utils/store';
import { Theme } from '../../../../components/Theme';
import { StatusTemplateCreationContextualMutation$data } from './__generated__/StatusTemplateCreationContextualMutation.graphql';
import { StatusTemplatesLinesPaginationQuery$variables } from './__generated__/StatusTemplatesLinesPaginationQuery.graphql';

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
    right: 230,
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
  dialog: {
    overflow: 'hidden',
  },
}));

const statusTemplateMutation = graphql`
  mutation StatusTemplateCreationMutation($input: StatusTemplateAddInput!) {
    statusTemplateAdd(input: $input) {
      ...StatusTemplateLine_node
    }
  }
`;

const statusTemplateContextualMutation = graphql`
  mutation StatusTemplateCreationContextualMutation(
    $input: StatusTemplateAddInput!
  ) {
    statusTemplateAdd(input: $input) {
      id
      name
    }
  }
`;

const statusTemplateValidation = (t: (name: string | object) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  color: Yup.string().required(t('This field is required')),
});

interface StatusTemplateCreationProps {
  contextual: boolean;
  inputValueContextual: string;
  creationCallback: (
    data: StatusTemplateCreationContextualMutation$data
  ) => void;
  handleCloseContextual: () => void;
  openContextual: boolean;
  paginationOptions?: StatusTemplatesLinesPaginationQuery$variables;
}

const StatusTemplateCreation: FunctionComponent<
StatusTemplateCreationProps
> = ({
  contextual,
  inputValueContextual,
  creationCallback,
  handleCloseContextual,
  openContextual,
  paginationOptions,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);

  const handleClose = () => setOpen(false);

  const onSubmit: FormikConfig<{ name: string; color: string }>['onSubmit'] = (
    values,
    { setSubmitting, resetForm },
  ) => {
    commitMutation({
      mutation: contextual
        ? statusTemplateContextualMutation
        : statusTemplateMutation,
      variables: {
        input: values,
      },
      setSubmitting,
      updater: (store: RecordSourceSelectorProxy) => {
        if (!contextual) {
          insertNode(
            store,
            'Pagination_statusTemplates',
            paginationOptions,
            'statusTemplateAdd',
          );
        }
      },
      onCompleted: (
        response: StatusTemplateCreationContextualMutation$data,
      ) => {
        setSubmitting(false);
        resetForm();
        if (contextual) {
          creationCallback(response);
          handleCloseContextual();
        } else {
          handleClose();
        }
      },
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
    });
  };

  const onResetClassic = () => handleClose();

  const onResetContextual = () => handleCloseContextual();

  const renderClassic = () => {
    return (
      <>
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
          sx={{ zIndex: 1202 }}
          elevation={1}
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
              {t('Create a status template')}
            </Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                color: '',
              }}
              validationSchema={statusTemplateValidation(t)}
              onSubmit={onSubmit}
              onReset={onResetClassic}
            >
              {({ submitForm, handleReset, isSubmitting }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t('Color')}
                    fullWidth={true}
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
      </>
    );
  };

  const renderContextual = () => {
    return (
      <div>
        <Formik
          enableReinitialize={true}
          initialValues={{
            name: inputValueContextual,
            color: '',
          }}
          validationSchema={statusTemplateValidation(t)}
          onSubmit={onSubmit}
          onReset={onResetContextual}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Dialog
                open={openContextual}
                PaperProps={{ elevation: 1 }}
                onClose={handleCloseContextual}
                fullWidth={true}
              >
                <DialogTitle>{t('Create a status template')}</DialogTitle>
                <DialogContent classes={{ root: classes.dialog }}>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="name"
                    label={t('Name')}
                    fullWidth={true}
                  />
                  <Field
                    component={ColorPickerField}
                    name="color"
                    label={t('Color')}
                    fullWidth={true}
                    style={{ marginTop: 20 }}
                  />
                </DialogContent>
                <DialogActions>
                  <Button onClick={handleReset} disabled={isSubmitting}>
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
              </Dialog>
            </Form>
          )}
        </Formik>
      </div>
    );
  };

  return contextual ? renderContextual() : renderClassic();
};

export default StatusTemplateCreation;
