import React, { useState } from 'react';
import * as R from 'ramda';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useCustomYup } from '../../../../utils/hooks/useEntitySettings';

const useStyles = makeStyles((theme) => ({
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
    zIndex: 2000,
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

const narrativeMutation = graphql`
  mutation NarrativeCreationMutation($input: NarrativeAddInput!) {
    narrativeAdd(input: $input) {
      id
      name
      description
      isSubNarrative
      subNarratives {
        edges {
          node {
            id
            name
            description
          }
        }
      }
    }
  }
`;

const narrativeValidation = (t) => {
  let shape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string()
      .min(3, t('The value is too short'))
      .max(5000, t('The value is too long'))
      .required(t('This field is required')),
  };

  shape = useCustomYup('Narrative', shape, t);

  return Yup.object().shape(shape);
};

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_narratives',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const NarrativeCreation = ({ paginationOptions, contextual, display }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const onReset = () => handleClose();

  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const finalValues = R.pipe(
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commitMutation({
      mutation: narrativeMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('narrativeAdd');
        const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(
          store,
          container.getDataID(),
          paginationOptions,
          newEdge,
        );
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };

  const fields = (setFieldValue, values) => (
    <React.Fragment>
      <Field
        component={TextField}
        variant="standard"
        name="name"
        label={t('Name')}
        fullWidth={true}
        detectDuplicate={['Narrative']}
      />
      <Field
        component={MarkDownField}
        name="description"
        label={t('Description')}
        fullWidth={true}
        multiline={true}
        rows="4"
        style={{ marginTop: 20 }}
      />
      <CreatedByField
        name="createdBy"
        style={{ marginTop: 20, width: '100%' }}
        setFieldValue={setFieldValue}
      />
      <ObjectLabelField
        name="objectLabel"
        style={{ marginTop: 20, width: '100%' }}
        setFieldValue={setFieldValue}
        values={values.objectLabel}
      />
      <ObjectMarkingField
        name="objectMarking"
        style={{ marginTop: 20, width: '100%' }}
      />
      <ExternalReferencesField
        name="externalReferences"
        style={{ marginTop: 20, width: '100%' }}
        setFieldValue={setFieldValue}
        values={values.externalReferences}
      />
    </React.Fragment>
  );

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
            <Typography variant="h6">{t('Create a narrative')}</Typography>
          </div>
          <div className={classes.container}>
            <Formik
              initialValues={{
                name: '',
                description: '',
                createdBy: '',
                objectMarking: [],
                objectLabel: [],
                externalReferences: [],
              }}
              validationSchema={narrativeValidation(t)}
              onSubmit={onSubmit}
              onReset={onReset}
            >
              {({
                submitForm,
                handleReset,
                isSubmitting,
                setFieldValue,
                values,
              }) => (
                <Form style={{ margin: '20px 0 20px 0' }}>
                  {fields(setFieldValue, values)}
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
        <Fab
          onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButtonContextual}
        >
          <Add />
        </Fab>
        <Dialog
          open={open}
          onClose={handleClose}
          PaperProps={{ elevation: 1 }}
        >
          <Formik
            initialValues={{
              name: '',
              description: '',
              createdBy: '',
              objectMarking: [],
              objectLabel: [],
              externalReferences: [],
            }}
            validationSchema={narrativeValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form>
                <DialogTitle>{t('Create a narrative')}</DialogTitle>
                <DialogContent>
                  {fields(setFieldValue, values)}
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
              </Form>
            )}
          </Formik>
        </Dialog>
      </div>
    );
  };

  if (contextual) {
    return renderContextual();
  }
  return renderClassic();
};

export default NarrativeCreation;
