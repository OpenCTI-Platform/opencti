import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import MenuItem from '@mui/material/MenuItem';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useYupSschemaBuilder } from '../../../../utils/hooks/useEntitySettings';

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

const organizationMutation = graphql`
  mutation OrganizationCreationMutation($input: OrganizationAddInput!) {
    organizationAdd(input: $input) {
      ...OrganizationLine_node
    }
  }
`;

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_organizations',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

const OrganizationCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const basicShape = {
    name: Yup.string().required(t('This field is required')),
    description: Yup.string().nullable(),
    x_opencti_organization_type: Yup.string().nullable(),
    x_opencti_reliability: Yup.string().nullable(),
  };
  const organizationValidator = useYupSschemaBuilder('Organization', basicShape);

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
      mutation: organizationMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        const payload = store.getRootField('organizationAdd');
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
          <Typography variant="h6">{t('Create an organization')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              description: '',
              x_opencti_reliability: '',
              x_opencti_organization_type: 'other',
              createdBy: '',
              objectMarking: [],
              objectLabel: [],
              externalReferences: [],
            }}
            validationSchema={organizationValidator}
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
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                  detectDuplicate={['Organization']}
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
                { /* TODO Improve customization (vocab with letter range) 2662 */}
                <Field
                  component={SelectField}
                  variant="standard"
                  name="x_opencti_organization_type"
                  label={t('Organization type')}
                  fullWidth={true}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                >
                  <MenuItem value="constituent">{t('Constituent')}</MenuItem>
                  <MenuItem value="csirt">{t('CSIRT')}</MenuItem>
                  <MenuItem value="partner">{t('Partner')}</MenuItem>
                  <MenuItem value="vendor">{t('Vendor')}</MenuItem>
                  <MenuItem value="other">{t('Other')}</MenuItem>
                </Field>
                <Field
                  component={SelectField}
                  variant="standard"
                  name="x_opencti_reliability"
                  label={t('Reliability')}
                  fullWidth={true}
                  containerstyle={{ marginTop: 20, width: '100%' }}
                >
                  <MenuItem value="A">{t('reliability_A')}</MenuItem>
                  <MenuItem value="B">{t('reliability_B')}</MenuItem>
                  <MenuItem value="C">{t('reliability_C')}</MenuItem>
                  <MenuItem value="D">{t('reliability_D')}</MenuItem>
                  <MenuItem value="E">{t('reliability_E')}</MenuItem>
                  <MenuItem value="F">{t('reliability_F')}</MenuItem>
                </Field>
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

export default OrganizationCreation;
