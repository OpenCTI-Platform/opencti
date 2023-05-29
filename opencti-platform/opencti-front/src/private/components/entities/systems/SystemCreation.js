import React, { useState } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as R from 'ramda';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleErrorInForm } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectLabelField from '../../common/form/ObjectLabelField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import MarkDownField from '../../../../components/MarkDownField';
import { ExternalReferencesField } from '../../common/form/ExternalReferencesField';
import { useSchemaCreationValidation } from '../../../../utils/hooks/useEntitySettings';
import { insertNode } from '../../../../utils/store';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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

const systemMutation = graphql`
  mutation SystemCreationMutation($input: SystemAddInput!) {
    systemAdd(input: $input) {
      id
      name
      description
      entity_type
      parent_types
      ...SystemLine_node
    }
  }
`;

export const SystemCreationForm = ({ updater, onReset, onCompleted,
  defaultCreatedBy, defaultMarkingDefinitions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const basicShape = {
    name: Yup.string().min(2).required(t('This field is required')),
    description: Yup.string().nullable(),
  };
  const systemValidator = useSchemaCreationValidation('System', basicShape);
  const onSubmit = (values, { setSubmitting, setErrors, resetForm }) => {
    const finalValues = R.pipe(
      R.assoc('createdBy', values.createdBy?.value),
      R.assoc('objectMarking', R.pluck('value', values.objectMarking)),
      R.assoc('objectLabel', R.pluck('value', values.objectLabel)),
      R.assoc('externalReferences', R.pluck('value', values.externalReferences)),
    )(values);
    commitMutation({
      mutation: systemMutation,
      variables: {
        input: finalValues,
      },
      updater: (store) => {
        if (updater) {
          updater(store, 'systemAdd');
        }
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        if (onCompleted) {
          onCompleted();
        }
      },
    });
  };

  return <Formik
      initialValues={{
        name: '',
        description: '',
        createdBy: defaultCreatedBy ?? '',
        objectMarking: defaultMarkingDefinitions ?? [],
        objectLabel: [],
        externalReferences: [],
      }}
      validationSchema={systemValidator}
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
              detectDuplicate={['User']}
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
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
          />
          <ObjectLabelField
              name="objectLabel"
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
              values={values.objectLabel}
          />
          <ObjectMarkingField
              name="objectMarking"
              style={fieldSpacingContainerStyle}
          />
          <ExternalReferencesField
              name="externalReferences"
              style={fieldSpacingContainerStyle}
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
  </Formik>;
};

const SystemCreation = ({ paginationOptions }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const updater = (store) => insertNode(
    store,
    'Pagination_systems',
    paginationOptions,
    'systemAdd',
  );

  return (
      <div>
        <Fab onClick={handleOpen}
          color="secondary"
          aria-label="Add"
          className={classes.createButton}>
          <Add />
        </Fab>
        <Drawer open={open}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={handleClose}>
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
            <Typography variant="h6">{t('Create a system')}</Typography>
          </div>
          <div className={classes.container}>
            <SystemCreationForm updater={updater} onCompleted={handleClose} onReset={handleClose}/>
          </div>
        </Drawer>
      </div>
  );
};

export default SystemCreation;
