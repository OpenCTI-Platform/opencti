import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import { Button } from '@mui/material';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import CreateEntityControlledDial from '../../../../components/CreateEntityControlledDial';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import type { Theme } from '../../../../components/Theme';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';

const ssoDefinitionMutation = graphql`
  mutation SSODefinitionCreationMutation(
    $input: SingleSignOnAddInput!
  ) {
    singleSignOnAdd(input: $input) {
      ...SSODefinitionsLine_node
    }
  }
`;

const CreateSSODefinitionControlledDial = (
  props: DrawerControlledDialProps,
) => (
  <CreateEntityControlledDial
    entityType="SSODefinition"
    {...props}
  />
);

interface SSODefinitionCreationProps {
  paginationOptions: PaginationOptions;
}

const SSODefinitionCreation: FunctionComponent<
  SSODefinitionCreationProps
> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const ssoDefinitionValidation = Yup.object().shape({
    strategy: Yup.string().required(t_i18n('This field is required')),
    name: Yup.string().required(t_i18n('This field is required')),
  });

  const initialValues = {
    name: '',
    strategy: '',
    enabled: true,
  };

  const onSubmit = (
    values: typeof initialValues,
    { setSubmitting, resetForm }: {
      setSubmitting: (flag: boolean) => void;
      resetForm: () => void;
    },
  ) => {
    const finalValues = {
      ...values,
    };
    commitMutation({
      ...defaultCommitMutation,
      mutation: ssoDefinitionMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_singleSignOns',
          paginationOptions,
          'singleSignOnAdd',
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
      title={t_i18n('Create a single sign on')}
      controlledDial={CreateSSODefinitionControlledDial}
    >
      {({ onClose }) => (
        <Formik
          initialValues={initialValues}
          validationSchema={ssoDefinitionValidation}
          onSubmit={onSubmit}
          onReset={onClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <Form>
              <Field
                component={SwitchField}
                variant="standard"
                name="enabled"
                label="Enable authentication methode"
                containerstyle={{ marginLeft: 2, marginTop: 20 }}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="strategy"
                label={t_i18n('Authentication Type')}
                containerstyle={{ width: '100%', marginTop: 20 }}
              >
                <MenuItem key="openID" value="OpenIDConnectStrategy">{t_i18n('OpenID')}</MenuItem>
                <MenuItem key="saml" value="SamlStrategy">{t_i18n('SAML')}</MenuItem>
                <MenuItem key="header" value="HeaderStrategy">{t_i18n('Header')}</MenuItem>
                <MenuItem key="client-cert" value="ClientCertStrategy">{t_i18n('Client')}</MenuItem>
                <MenuItem key="local" value="LocalStrategy">{t_i18n('Local')}</MenuItem>
              </Field>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
                style={{ marginTop: 20 }}
              />
              <div style={{
                marginTop: 20,
                textAlign: 'right',
              }}
              >
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  style={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default SSODefinitionCreation;
