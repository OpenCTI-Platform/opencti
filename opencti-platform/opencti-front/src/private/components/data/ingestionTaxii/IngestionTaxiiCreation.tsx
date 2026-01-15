import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Button from '@common/button/Button';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import MenuItem from '@mui/material/MenuItem';
import { BASIC_AUTH, BEARER_AUTH, CERT_AUTH, getAuthenticationValue } from '../../../../utils/ingestionAuthentificationUtils';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle, FieldOption } from '../../../../utils/field';
import { insertNode } from '../../../../utils/store';
import SelectField from '../../../../components/fields/SelectField';
import DateTimePickerField from '../../../../components/DateTimePickerField';
import SwitchField from '../../../../components/fields/SwitchField';
import PasswordTextField from '../../../../components/PasswordTextField';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import IngestionCreationUserHandling from '@components/data/IngestionCreationUserHandling';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { PaginationOptions } from '../../../../components/list_lines';
import { IngestionTaxiiImportQuery$data } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiImportQuery.graphql';
import { FormikHelpers } from 'formik/dist/types';
import FormButtonContainer from '@common/form/FormButtonContainer';

const IngestionTaxiiCreationMutation = graphql`
  mutation IngestionTaxiiCreationMutation($input: IngestionTaxiiAddInput!) {
    ingestionTaxiiAdd(input: $input) {
      ...IngestionTaxiiLine_node
    }
  }
`;

const ingestionTaxiiCreationValidation = () => {
  const { t_i18n } = useFormatter();
  return Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    uri: Yup.string().required(t_i18n('This field is required')),
    version: Yup.string().required(t_i18n('This field is required')),
    collection: Yup.string().required(t_i18n('This field is required')),
    authentication_type: Yup.string().required(t_i18n('This field is required')),
    authentication_value: Yup.string().nullable(),
    username: Yup.string().nullable(),
    password: Yup.string().nullable(),
    cert: Yup.string().nullable(),
    key: Yup.string().nullable(),
    ca: Yup.string().nullable(),
    user_id: Yup.object().nullable(),
    added_after_start: Yup.date()
      .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)'))
      .nullable(),
    confidence_to_score: Yup.bool().nullable(),
  });
};

interface IngestionTaxiiAddInput {
  name: string;
  description?: string | null;
  uri: string;
  version: string;
  collection: string;
  authentication_type: string;
  authentication_value?: string;
  added_after_start?: Date | null;
  user_id: string | FieldOption;
  automatic_user?: boolean;
  confidence_level?: string;
  username?: string;
  password?: string;
  cert?: string;
  key?: string;
  ca?: string;
  confidence_to_score?: boolean;
}

interface IngestionTaxiiCreationProps {
  paginationOptions?: PaginationOptions;
  handleClose?: () => void;
  ingestionTaxiiData?: IngestionTaxiiImportQuery$data['taxiiFeedAddInputFromImport'];
  triggerButton?: boolean;
  open?: boolean;
  drawerSettings?: {
    title: string;
    button: string;
  };
}

const CreateIngestionTaxiiControlledDial = (props: DrawerControlledDialProps) => (
  <CreateEntityControlledDial
    entityType="IngestionTaxii"
    {...props}
  />
);

const IngestionTaxiiCreation: FunctionComponent<IngestionTaxiiCreationProps> = ({
  paginationOptions,
  handleClose,
  ingestionTaxiiData,
  triggerButton = true,
  open = false,
  drawerSettings,
}) => {
  const { t_i18n } = useFormatter();

  const [commit] = useApiMutation(IngestionTaxiiCreationMutation);

  const handleSubmit = (values: IngestionTaxiiAddInput, { setSubmitting, resetForm }: FormikHelpers<IngestionTaxiiAddInput>) => {
    const authenticationValue = getAuthenticationValue(values);
    const userId
      = typeof values.user_id === 'object'
        ? values.user_id?.value
        : values.user_id;
    const input = {
      name: values.name,
      description: values.description,
      uri: values.uri,
      version: values.version,
      collection: values.collection,
      authentication_type: values.authentication_type,
      authentication_value: authenticationValue,
      added_after_start: values.added_after_start,
      user_id: userId,
      automatic_user: values.automatic_user ?? true,
      ...((values.automatic_user !== false) && { confidence_level: Number(values.confidence_level) }),
      confidence_to_score: values.confidence_to_score,
    };

    commit({
      variables: {
        input,
      },
      updater: (store) => {
        insertNode(
          store,
          'Pagination_ingestionTaxiis',
          paginationOptions,
          'ingestionTaxiiAdd',
        );
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const initialValues: IngestionTaxiiAddInput = {
    name: ingestionTaxiiData?.name || '',
    description: ingestionTaxiiData?.description || '',
    uri: ingestionTaxiiData?.uri || '',
    version: ingestionTaxiiData?.version || '',
    collection: ingestionTaxiiData?.collection || '',
    added_after_start: ingestionTaxiiData?.added_after_start ? new Date(ingestionTaxiiData?.added_after_start) : null,
    authentication_type: ingestionTaxiiData?.authentication_type || 'none',
    user_id: '',
    automatic_user: true,
    confidence_to_score: false,
  };

  return (
    <Drawer
      title={drawerSettings?.title ?? t_i18n('Create a TAXII ingester')}
      open={open}
      onClose={handleClose}
      controlledDial={triggerButton ? CreateIngestionTaxiiControlledDial : undefined}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={ingestionTaxiiCreationValidation()}
          onSubmit={handleSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting, values }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                name="uri"
                label={t_i18n('TAXII server URL')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="version"
                label={t_i18n('TAXII version')}
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
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="authentication_type"
                label={t_i18n('Authentication type')}
                fullWidth={true}
                containerstyle={{
                  width: '100%',
                  marginTop: 20,
                }}
              >
                <MenuItem value="none">{t_i18n('None')}</MenuItem>
                <MenuItem value="basic">
                  {t_i18n('Basic user / password')}
                </MenuItem>
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
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="password"
                    label={t_i18n('Password')}
                  />
                </>
              )}
              {values.authentication_type === BEARER_AUTH && (
                <PasswordTextField
                  name="authentication_value"
                  label={t_i18n('Token')}
                />
              )}
              {values.authentication_type === CERT_AUTH && (
                <>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="cert"
                    label={t_i18n('Certificate (base64)')}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                  <PasswordTextField
                    name="key"
                    label={t_i18n('Key (base64)')}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="ca"
                    label={t_i18n('CA certificate (base64)')}
                    fullWidth={true}
                    style={fieldSpacingContainerStyle}
                  />
                </>
              )}
              <IngestionCreationUserHandling
                default_confidence_level={50}
                labelTag="F"
              />
              <Field
                component={DateTimePickerField}
                name="added_after_start"
                textFieldProps={{
                  label: t_i18n(
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
                label={t_i18n('Copy confidence level to OpenCTI scores for indicators')}
                containerstyle={fieldSpacingContainerStyle}
              />
              <FormButtonContainer>
                <Button
                  variant="secondary"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting}

                >
                  {drawerSettings?.button ?? t_i18n('Create')}
                </Button>
              </FormButtonContainer>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default IngestionTaxiiCreation;
