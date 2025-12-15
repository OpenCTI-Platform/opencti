import React from 'react';
import * as PropTypes from 'prop-types';
import { Field, Form, Formik } from 'formik';
import withStyles from '@mui/styles/withStyles';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import { BASIC_AUTH, BEARER_AUTH, CERT_AUTH, getAuthenticationValue } from '../../../../utils/ingestionAuthentificationUtils';
import Drawer from '../../common/drawer/Drawer';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import CreatorField from '../../common/form/CreatorField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import SelectField from '../../../../components/fields/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import SwitchField from '../../../../components/fields/SwitchField';
import PasswordTextField from '../../../../components/PasswordTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';

const styles = (theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
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
  added_after_start: Yup.date()
    .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
    .nullable(),
  confidence_to_score: Yup.bool().nullable(),
});

const CreateIngestionTaxiiControlledDial = (props) => (
  <CreateEntityControlledDial
    entityType="IngestionTaxii"
    {...props}
  />
);

const IngestionTaxiiCreation = (props) => {
  const { t, classes } = props;

  const onSubmit = (values, { setSubmitting, resetForm }) => {
    const authentifcationValueResolved = getAuthenticationValue(values);

    const input = {
      name: values.name,
      description: values.description,
      uri: values.uri,
      version: values.version,
      collection: values.collection,
      authentication_type: values.authentication_type,
      authentication_value: authentifcationValueResolved,
      added_after_start: values.added_after_start,
      user_id: values.user_id?.value,
      confidence_to_score: values.confidence_to_score,
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
      },
    });
  };

  return (
    <Drawer
      title={t('Create a TAXII ingester')}
      controlledDial={CreateIngestionTaxiiControlledDial}
    >
      {({ onClose }) => (
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
            confidence_to_score: false,
          }}
          validationSchema={ingestionTaxiiCreationValidation(t)}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, values }) => (
            <Form>
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
              {values.authentication_type === BASIC_AUTH && (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="username"
                    label={t('Username')}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="password"
                    label={t('Password')}
                  />
                </>
              )}
              {values.authentication_type === BEARER_AUTH && (
                <PasswordTextField
                  name="authentication_value"
                  label={t('Token')}
                />
              )}
              {values.authentication_type === CERT_AUTH && (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="cert"
                    label={t('Certificate (base64)')}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="key"
                    label={t('Key (base64)')}
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
                label={t('User responsible for data creation (empty = System)')}
                containerStyle={fieldSpacingContainerStyle}
                showConfidence
              />
              <Field
                component={DateTimePickerField}
                name="added_after_start"
                textFieldProps={{
                  label: t(
                    'Import from date (empty = all TAXII collection possible items)',
                  ),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="confidence_to_score"
                label={t('Copy confidence level to OpenCTI scores for indicators')}
                containerstyle={fieldSpacingContainerStyle}
              />
              <div className={classes.buttons}>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Cancel')}
                </Button>
                <Button
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
      )}
    </Drawer>
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
