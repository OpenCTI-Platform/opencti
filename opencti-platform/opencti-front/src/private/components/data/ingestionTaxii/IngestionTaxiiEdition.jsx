import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import * as R from 'ramda';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatorField from '../../common/form/CreatorField';
import { convertUser } from '../../../../utils/edition';
import SelectField from '../../../../components/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import Drawer from '../../common/drawer/Drawer';
import { useSchemaEditionValidation, useMandatorySchemaAttributes } from '../../../../utils/hooks/useSchemaAttributes';

export const ingestionTaxiiMutationFieldPatch = graphql`
  mutation IngestionTaxiiEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    ingestionTaxiiFieldPatch(id: $id, input: $input) {
      ...IngestionTaxiiEdition_ingestionTaxii
    }
  }
`;

const OBJECT_TYPE = 'IngestionTaxii';

const IngestionTaxiiEditionContainer = ({
  t,
  open,
  handleClose,
  ingestionTaxii,
}) => {
  const basicShape = {
    name: Yup.string(),
    description: Yup.string().nullable(),
    uri: Yup.string(),
    version: Yup.string(),
    collection: Yup.string(),
    authentication_type: Yup.string(),
    authentication_value: Yup.string().nullable(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    user_id: Yup.mixed().nullable(),
    added_after_start: Yup.date()
      .typeError(t('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
  };
  const mandatoryAttributes = useMandatorySchemaAttributes(OBJECT_TYPE);
  const validator = useSchemaEditionValidation(
    OBJECT_TYPE,
    basicShape,
  );

  const handleSubmitField = (name, value) => {
    validator
      .validateAt(name, { [name]: value })
      .then(() => {
        let finalName = name;
        let finalValue = value;
        if (name === 'user_id') {
          finalValue = value?.value;
        }
        if (name === 'username') {
          finalName = 'authentication_value';
          finalValue = `${value}:${
            ingestionTaxii.authentication_value.split(':')[1]
          }`;
        }
        if (name === 'password') {
          finalName = 'authentication_value';
          finalValue = `${
            ingestionTaxii.authentication_value.split(':')[0]
          }:${value}`;
        }
        if (name === 'cert') {
          finalName = 'authentication_value';
          finalValue = `${value}:${
            ingestionTaxii.authentication_value.split(':')[1]
          }:${ingestionTaxii.authentication_value.split(':')[2]}`;
        }
        if (name === 'key') {
          finalName = 'authentication_value';
          finalValue = `${
            ingestionTaxii.authentication_value.split(':')[0]
          }:${value}:${ingestionTaxii.authentication_value.split(':')[2]}`;
        }
        if (name === 'ca') {
          finalName = 'authentication_value';
          finalValue = `${ingestionTaxii.authentication_value.split(':')[0]}:${
            ingestionTaxii.authentication_value.split(':')[1]
          }:${value}`;
        }
        commitMutation({
          mutation: ingestionTaxiiMutationFieldPatch,
          variables: {
            id: ingestionTaxii.id,
            input: { key: finalName, value: finalValue || '' },
          },
        });
      })
      .catch(() => false);
  };
  const initialValues = R.pipe(
    R.assoc('user_id', convertUser(ingestionTaxii, 'user')),
    R.assoc(
      'username',
      ingestionTaxii.authentication_type === 'basic'
        ? ingestionTaxii.authentication_value.split(':')[0]
        : '',
    ),
    R.assoc(
      'password',
      ingestionTaxii.authentication_type === 'basic'
        ? ingestionTaxii.authentication_value.split(':')[1]
        : '',
    ),
    R.assoc(
      'cert',
      ingestionTaxii.authentication_type === 'certificate'
        ? ingestionTaxii.authentication_value.split(':')[0]
        : '',
    ),
    R.assoc(
      'key',
      ingestionTaxii.authentication_type === 'certificate'
        ? ingestionTaxii.authentication_value.split(':')[1]
        : '',
    ),
    R.assoc(
      'ca',
      ingestionTaxii.authentication_type === 'certificate'
        ? ingestionTaxii.authentication_value.split(':')[2]
        : '',
    ),
    R.pick([
      'name',
      'description',
      'uri',
      'version',
      'collection',
      'authentication_type',
      'authentication_value',
      'username',
      'password',
      'cert',
      'key',
      'ca',
      'user_id',
      'added_after_start',
    ]),
  )(ingestionTaxii);

  return (
    <Drawer
      title={t('Update a TAXII ingester')}
      open={open}
      onClose={handleClose}
    >
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={validator}
      >
        {({ values }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={TextField}
              variant="standard"
              name="name"
              label={t('Name')}
              required={(mandatoryAttributes.includes('name'))}
              fullWidth={true}
              onSubmit={handleSubmitField}
            />
            <Field
              component={TextField}
              variant="standard"
              name="description"
              label={t('Description')}
              required={(mandatoryAttributes.includes('description'))}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
              onSubmit={handleSubmitField}
            />
            <Field
              component={TextField}
              variant="standard"
              name="uri"
              label={t('TAXII server URL')}
              required={(mandatoryAttributes.includes('uri'))}
              fullWidth={true}
              onSubmit={handleSubmitField}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SelectField}
              variant="standard"
              name="version"
              label={t('TAXII version')}
              required={(mandatoryAttributes.includes('version'))}
              onSubmit={handleSubmitField}
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
              required={(mandatoryAttributes.includes('collection'))}
              onSubmit={handleSubmitField}
              fullWidth={true}
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={SelectField}
              variant="standard"
              name="authentication_type"
              label={t('Authentication type')}
              required={(mandatoryAttributes.includes('authentication_type'))}
              onSubmit={handleSubmitField}
              fullWidth={true}
              containerstyle={{
                width: '100%',
                marginTop: 20,
              }}
            >
              <MenuItem value="none">{t('None')}</MenuItem>
              <MenuItem value="basic">{t('Basic user / password')}</MenuItem>
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
                  required={(mandatoryAttributes.includes('username'))}
                  onSubmit={handleSubmitField}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="password"
                  label={t('Password')}
                  required={(mandatoryAttributes.includes('password'))}
                  onSubmit={handleSubmitField}
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
                required={(mandatoryAttributes.includes('authentication_value'))}
                onSubmit={handleSubmitField}
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
                  required={(mandatoryAttributes.includes('cert'))}
                  onSubmit={handleSubmitField}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="key"
                  label={t('Key (base64)')}
                  required={(mandatoryAttributes.includes('key'))}
                  onSubmit={handleSubmitField}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="ca"
                  label={t('CA certificate (base64)')}
                  required={(mandatoryAttributes.includes('ca'))}
                  onSubmit={handleSubmitField}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
              </>
            )}
            <Field
              component={DateTimePickerField}
              name="added_after_start"
              onSubmit={handleSubmitField}
              textFieldProps={{
                label: t(
                  'Import from date (empty = all TAXII collection possible items)',
                ),
                fullWidth: true,
                style: { marginTop: 20 },
              }}
              required={(mandatoryAttributes.includes('added_after_start'))}
            />
            <CreatorField
              name="user_id"
              label={t('User responsible for data creation (empty = System)')}
              required={(mandatoryAttributes.includes('user_id'))}
              onChange={handleSubmitField}
              containerStyle={fieldSpacingContainerStyle}
            />
          </Form>
        )}
      </Formik>
    </Drawer>
  );
};

IngestionTaxiiEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  ingestionTaxii: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const IngestionTaxiiEditionFragment = createFragmentContainer(
  IngestionTaxiiEditionContainer,
  {
    ingestionTaxii: graphql`
      fragment IngestionTaxiiEdition_ingestionTaxii on IngestionTaxii {
        id
        name
        uri
        version
        collection
        ingestion_running
        added_after_start
        authentication_type
        authentication_value
        user {
          id
          entity_type
          name
        }
      }
    `,
  },
);

export default R.compose(
  inject18n,
)(IngestionTaxiiEditionFragment);
