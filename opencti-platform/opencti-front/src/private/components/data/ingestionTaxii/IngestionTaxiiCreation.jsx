import React, { useState } from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Fab from '@mui/material/Fab';
import { Add, Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import OpenVocabField from '../../common/form/OpenVocabField';
import CreatedByField from '../../common/form/CreatedByField';
import ObjectMarkingField from '../../common/form/ObjectMarkingField';
import { insertNode } from '../../../../utils/store';
import SelectField from '../../../../components/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';

const styles = (theme) => ({
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
    padding: '20px 0px 20px 60px',
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
  title: {
    float: 'left',
  },
});

const IngestionTaxiiCreationMutation = graphql`
  mutation IngestionTaxiiCreationMutation($input: IngestionTaxiiAddInput!) {
    ingestionTaxiiAdd(input: $input) {
      ...IngestionTaxiiLine_node
    }
  }
`;

const ingestionTaxiiCreationValidation = (t) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  uri: Yup.string().required(t('This field is required')),
  version: Yup.string().required(t('This field is required')),
  collection: Yup.string().required(t('This field is required')),
  authentication_type: Yup.string().required(t('This field is required')),
  authentication_value: Yup.string().nullable(),
  username: Yup.string().nullable(),
  password: Yup.string().nullable(),
  cert: Yup.string().nullable(),
  key: Yup.string().nullable(),
  ca: Yup.string().nullable(),
  user_id: Yup.object().nullable(),
});

const IngestionTaxiiCreation = (props) => {
  const { t, classes } = props;
  const [open, setOpen] = useState(false);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };
  const onSubmit = (values, { setSubmitting, resetForm }) => {
    let authentifcationValue = values.authentication_value;
    if (values.authentication_type === 'basic') {
      authentifcationValue = `${values.username}:${values.password}`;
    } else if (values.authentication_type === 'certificate') {
      authentifcationValue = `${values.cert}:${values.key}:${values.ca}`;
    }
    const input = {
      name: values.name,
      description: values.description,
      uri: values.uri,
      version: values.version,
      collection: values.collection,
      authentication_type: values.authentication_type,
      authentication_value: authentifcationValue,
      added_after_start: values.added_after_start,
      user_id: values.user_id?.value,
    };
    commitMutation({
      mutation: IngestionTaxiiCreationMutation,
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_ingestionTaxiis',
          props.paginationOptions,
          'ingestionTaxiiAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleClose();
      },
    });
  };
  const onReset = () => {
    handleClose();
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
          <Typography variant="h6">{t('Create a TAXII ingester')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik
            initialValues={{
              name: '',
              description: '',
              uri: '',
              version: 'v21',
              collection: '',
              added_after_start: null,
              authentication_type: 'none',
              authentication_value: '',
              user_id: '',
              username: '',
              password: '',
              cert: '',
              key: '',
              ca: '',
            }}
            validationSchema={ingestionTaxiiCreationValidation(t)}
            onSubmit={onSubmit}
            onReset={onReset}
          >
            {({ submitForm, handleReset, isSubmitting, values }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="uri"
                  label={t('TAXII server URL')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="version"
                  label={t('TAXII version')}
                  fullWidth={true}
                  containerstyle={{
                    width: '100%',
                    marginTop: 20,
                  }}
                >
                  <MenuItem value="v1" disabled={true}>
                    {t('TAXII 1.0')}
                  </MenuItem>
                  <MenuItem value="v2" disabled={true}>
                    {t('TAXII 2.0')}
                  </MenuItem>
                  <MenuItem value="v21">{t('TAXII 2.1')}</MenuItem>
                </Field>
                <Field
                  component={TextField}
                  variant="standard"
                  name="collection"
                  label={t('TAXII Collection')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={SelectField}
                  variant="standard"
                  name="authentication_type"
                  label={t('Authentication type')}
                  fullWidth={true}
                  containerstyle={{
                    width: '100%',
                    marginTop: 20,
                  }}
                >
                  <MenuItem value="none">{t('None')}</MenuItem>
                  <MenuItem value="basic">
                    {t('Basic user / password')}
                  </MenuItem>
                  <MenuItem value="bearer">{t('Bearer token')}</MenuItem>
                  <MenuItem value="certificate">
                    {t('Client certificate')}
                  </MenuItem>
                </Field>
                {values.authentication_type === 'basic' && (
                  <>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="username"
                      label={t('Username')}
                      fullWidth={true}
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="password"
                      label={t('Password')}
                      fullWidth={true}
                      style={fieldSpacingContainerStyle}
                    />
                  </>
                )}
                {values.authentication_type === 'bearer' && (
                  <Field
                    component={TextField}
                    variant="standard"
                    name="authentication_value"
                    label={t('Token')}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                )}
                {values.authentication_type === 'certificate' && (
                  <>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="cert"
                      label={t('Certificate (base64)')}
                      fullWidth={true}
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="key"
                      label={t('Key (base64)')}
                      fullWidth={true}
                      style={fieldSpacingContainerStyle}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="ca"
                      label={t('CA certificate (base64)')}
                      fullWidth={true}
                      style={fieldSpacingContainerStyle}
                    />
                  </>
                )}
                <CreatorField
                  name="user_id"
                  label={t(
                    'User responsible for data creation (empty = System)',
                  )}
                  containerStyle={fieldSpacingContainerStyle}
                />
                <Field
                  component={DateTimePickerField}
                  name="added_after_start"
                  TextFieldProps={{
                    label: t(
                      'Import from date (empty = all TAXII collection possible items)',
                    ),
                    variant: 'standard',
                    fullWidth: true,
                    style: { marginTop: 20 },
                  }}
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

IngestionTaxiiCreation.propTypes = {
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(IngestionTaxiiCreation);
