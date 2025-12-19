import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, useMemo } from 'react';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { FormikConfig } from 'formik/dist/types';
import { ExternalReferencesValues } from '@components/common/form/ExternalReferencesField';
import {
  IngestionTaxiiEditionFragment_ingestionTaxii$data,
  IngestionTaxiiEditionFragment_ingestionTaxii$key,
} from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiEditionFragment_ingestionTaxii.graphql';
import CommitMessage from '@components/common/form/CommitMessage';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import CreatorField from '../../common/form/CreatorField';
import { convertUser } from '../../../../utils/edition';
import SelectField from '../../../../components/fields/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import {
  BASIC_AUTH,
  BEARER_AUTH,
  CERT_AUTH,
  extractCA,
  extractCert,
  extractKey,
  extractPassword,
  extractToken,
  extractUsername,
  updateAuthenticationFields,
} from '../../../../utils/ingestionAuthentificationUtils';
import SwitchField from '../../../../components/fields/SwitchField';
import PasswordTextField from '../../../../components/PasswordTextField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import { adaptFieldValue } from '../../../../utils/String';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const initIngestionValue = (ingestionTaxiiData: IngestionTaxiiEditionFragment_ingestionTaxii$data) => {
  return {
    ...{
      name: ingestionTaxiiData.name,
      description: ingestionTaxiiData.description,
      uri: ingestionTaxiiData.uri,
      version: ingestionTaxiiData.version,
      collection: ingestionTaxiiData.collection,
      authentication_type: ingestionTaxiiData.authentication_type,
      authentication_value: ingestionTaxiiData.authentication_value,
      user_id: convertUser(ingestionTaxiiData, 'user'),
      added_after_start: ingestionTaxiiData.added_after_start,
      confidence_to_score: ingestionTaxiiData.confidence_to_score,
    },
    ...(ingestionTaxiiData.authentication_type === BEARER_AUTH
      ? {
          token: extractToken(ingestionTaxiiData.authentication_value),
        }
      : {
          token: '',
        }),
    ...(ingestionTaxiiData.authentication_type === BASIC_AUTH
      ? {
          username: extractUsername(ingestionTaxiiData.authentication_value),
          password: extractPassword(ingestionTaxiiData.authentication_value),
        }
      : {
          username: '',
          password: '',
        }),
    ...(ingestionTaxiiData.authentication_type === CERT_AUTH
      ? {
          cert: extractCert(ingestionTaxiiData.authentication_value),
          key: extractKey(ingestionTaxiiData.authentication_value),
          ca: extractCA(ingestionTaxiiData.authentication_value),
        }
      : {
          cert: '',
          key: '',
          ca: '',
        }),
  };
};

export const ingestionTaxiiMutationFieldPatch = graphql`
  mutation IngestionTaxiiEditionFieldPatchMutation(
    $id: ID!
    $input: [EditInput!]!
  ) {
    ingestionTaxiiFieldPatch(id: $id, input: $input) {
      ...IngestionTaxiiEditionFragment_ingestionTaxii
    }
  }
`;

export const ingestionTaxiiEditionFragment = graphql`
  fragment IngestionTaxiiEditionFragment_ingestionTaxii on IngestionTaxii {
    id
    name
    description
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
    confidence_to_score
  }
`;

interface IngestionTaxiiEditionProps {
  ingestionTaxii: IngestionTaxiiEditionFragment_ingestionTaxii$key;
  handleClose: () => void;
  enableReferences?: boolean;
}

export interface IngestionTaxiiEditionForm {
  message?: string | null;
  references?: ExternalReferencesValues;
  name: string;
  description?: string | null | undefined;
  uri: string;
  version: string;
  collection: string;
  authentication_type: string;
  authentication_value?: string | null | undefined;
  token?: string;
  username?: string;
  password?: string;
  cert?: string;
  key?: string;
  ca?: string;
  user_id: string | FieldOption | null | undefined;
  added_after_start: Date | null | undefined;
  confidence_to_score: boolean | null | undefined;
}

const IngestionTaxiiEdition: FunctionComponent<IngestionTaxiiEditionProps> = ({
  ingestionTaxii,
  handleClose,
  enableReferences = false,

}) => {
  const { t_i18n } = useFormatter();
  const ingestionTaxiiData = useFragment(ingestionTaxiiEditionFragment, ingestionTaxii);

  const basicShape = {
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    version: Yup.string().required(t_i18n('This field is required')),
    collection: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    token: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    user_id: Yup.mixed().nullable(),
    added_after_start: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    confidence_to_score: Yup.bool().nullable(),
  };

  const ingestionTaxiiValidator = useSchemaEditionValidation('IngestionTaxii', basicShape);
  const [commitUpdate] = useApiMutation(ingestionTaxiiMutationFieldPatch);

  const onSubmit: FormikConfig<IngestionTaxiiEditionForm>['onSubmit'] = (values, { setSubmitting }) => {
    const { message, references, ...otherValues } = values;
    const commitMessage = message ?? '';
    const commitReferences = (references ?? []).map(({ value }) => value);
    const inputValues = Object.entries({
      ...otherValues,
    }).map(([key, value]) => ({ key, value: adaptFieldValue(value) }));
    commitUpdate({
      variables: {
        id: ingestionTaxiiData.id,
        input: inputValues,
        commitMessage: commitMessage && commitMessage.length > 0 ? commitMessage : null,
        references: commitReferences,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
    });
  };

  const handleSubmitField = (
    name: string,
    value: string | Date | boolean | FieldOption | null,
    values?: IngestionTaxiiEditionForm,
  ) => {
    let finalName = name;
    let finalValue = value as string | undefined;
    if (name === 'user_id') {
      finalValue = (value as FieldOption)?.value;
    }

    // region authentication -- If you change something here, please have a look at IngestionTaxiiEdition
    const { username, password, token, cert, key, ca } = values || {};

    if (name === 'token') {
      finalName = 'authentication_value';
      finalValue = token;
    }

    // re-compose username:password
    if (name === 'username') {
      finalName = 'authentication_value';
      finalValue = `${value}:${password}`;
    }
    if (name === 'password') {
      finalName = 'authentication_value';
      finalValue = `${username}:${value}`;
    }

    // re-compose cert:key:ca
    if (name === 'cert') {
      finalName = 'authentication_value';
      finalValue = `${value}:${key}:${ca}`;
    }
    if (name === 'key') {
      finalName = 'authentication_value';
      finalValue = `${cert}:${value}:${ca}`;
    }
    if (name === 'ca') {
      finalName = 'authentication_value';
      finalValue = `${cert}:${key}:${value}`;
    }
    // end region authentication

    ingestionTaxiiValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        commitUpdate({
          variables: {
            id: ingestionTaxiiData.id,
            input: [{ key: finalName, value: finalValue || '' }],
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = useMemo(() => initIngestionValue(ingestionTaxiiData), [ingestionTaxiiData.id]);

  return (
    <Formik<IngestionTaxiiEditionForm>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={ingestionTaxiiValidator}
      onSubmit={onSubmit}
    >
      {({
        values,
        submitForm,
        isSubmitting,
        setFieldValue,
        isValid,
        dirty,
      }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth={true}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
            onSubmit={handleSubmitField}
          />
          <Field
            component={TextField}
            variant="standard"
            name="uri"
            label={t_i18n('TAXII server URL')}
            fullWidth={true}
            onSubmit={handleSubmitField}
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="version"
            label={t_i18n('TAXII version')}
            onSubmit={handleSubmitField}
            fullWidth={true}
            containerstyle={{
              width: '100%',
              marginTop: 20,
            }}
          >
            <MenuItem value="v21">{t_i18n('TAXII 2.1')}</MenuItem>
          </Field>
          <Field
            component={TextField}
            variant="standard"
            name="collection"
            label={t_i18n('TAXII Collection')}
            onSubmit={handleSubmitField}
            fullWidth={true}
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="authentication_type"
            label={t_i18n('Authentication type')}
            onChange={(_: string, value: string) => updateAuthenticationFields(setFieldValue, value)}
            onSubmit={handleSubmitField}
            fullWidth={true}
            containerstyle={{
              width: '100%',
              marginTop: 20,
            }}
          >
            <MenuItem value="none">{t_i18n('None')}</MenuItem>
            <MenuItem value="basic">{t_i18n('Basic user / password')}</MenuItem>
            <MenuItem value="bearer">{t_i18n('Bearer token')}</MenuItem>
            <MenuItem value="certificate">
              {t_i18n('Client certificate')}
            </MenuItem>
          </Field>
          {values.authentication_type === BASIC_AUTH && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="username"
                label={t_i18n('Username')}
                onSubmit={(name: string, value: string) => handleSubmitField(name, value, values)}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <PasswordTextField
                name="password"
                label={t_i18n('Password')}
                isSecret
                onSubmit={(name: string, value: string) => handleSubmitField(name, value, values)}
              />
            </>
          )}
          {values.authentication_type === BEARER_AUTH && (
            <PasswordTextField
              name="token"
              label={t_i18n('Token')}
              isSecret
              onSubmit={(name: string, value: string) => handleSubmitField(name, value, values)}
            />
          )}
          {values.authentication_type === CERT_AUTH && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="cert"
                label={t_i18n('Certificate (base64)')}
                onSubmit={(name: string, value: string) => handleSubmitField(name, value, values)}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <PasswordTextField
                name="key"
                label={t_i18n('Key (base64)')}
                isSecret
                onSubmit={(name: string, value: string) => handleSubmitField(name, value, values)}
              />
              <Field
                component={TextField}
                variant="standard"
                name="ca"
                label={t_i18n('CA certificate (base64)')}
                onSubmit={(name: string, value: string) => handleSubmitField(name, value, values)}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
            </>
          )}
          {enableReferences && (
            <CommitMessage
              submitForm={submitForm}
              disabled={isSubmitting || !isValid || !dirty}
              setFieldValue={setFieldValue}
              open={false}
              values={values.references}
              id={ingestionTaxiiData.id}
            />
          )}
          <CreatorField
            name="user_id"
            label={t_i18n('User responsible for data creation (empty = System)')}
            onChange={handleSubmitField}
            containerStyle={fieldSpacingContainerStyle}
            showConfidence
          />
          <Field
            component={DateTimePickerField}
            name="added_after_start"
            onSubmit={handleSubmitField}
            textFieldProps={{
              label: t_i18n(
                'Import from date (empty = all TAXII collection possible items)',
              ),
              fullWidth: true,
              style: { marginTop: 20 },
            }}
          />
          <Field
            component={SwitchField}
            onChange={handleSubmitField}
            type="checkbox"
            name="confidence_to_score"
            label={t_i18n('Copy confidence level to OpenCTI scores for indicators')}
            containerstyle={fieldSpacingContainerStyle}
          />
        </Form>
      )}
    </Formik>
  );
};

export default IngestionTaxiiEdition;
