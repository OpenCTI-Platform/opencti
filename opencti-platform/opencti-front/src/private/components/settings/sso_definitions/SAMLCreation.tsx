import React, { FunctionComponent } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Button, IconButton } from '@mui/material';
import { TextField } from 'formik-mui';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import { Add, Delete } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import SwitchField from '../../../../components/fields/SwitchField';

export interface SAMLCreationValues {
  private_key: string;
  entity_id: string;
  idp_cert: string;
  saml_callback_url: string;
  want_assertions_signed: boolean;
  want_auth_response_signed: boolean;
  login_idp_directly: boolean;
  logout_remote: boolean;
  provider_method: string;
  idp_signing_certificate: string;
  sso_binding_type: string;
  force_reauthentication: boolean;
  enable_debug_mode: boolean;

  advancedConfigurations: {
    key: string;
    value: string;
    type: string;
  }[];
}

interface SAMLCreationProps {
  initialValues?: Partial<SAMLCreationValues>;
  onSubmit: (
    values: SAMLCreationValues,
    helpers: { setSubmitting: (b: boolean) => void; resetForm: () => void },
  ) => void;
}

const SAMLCreation: FunctionComponent<SAMLCreationProps> = ({
  initialValues,
  onSubmit,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const validationSchema = Yup.object().shape({
    entity_id: Yup.string().required(t_i18n('This field is required')),
    idp_cert: Yup.string().required(t_i18n('This field is required')),
    saml_callback_url: Yup.string().url(t_i18n('Must be a valid URL')).required(t_i18n('This field is required')),
  });

  const defaultValues: SAMLCreationValues = {
    private_key: '',
    entity_id: '',
    idp_cert: '',
    saml_callback_url: '',
    want_assertions_signed: false,
    want_auth_response_signed: false,
    login_idp_directly: false,
    logout_remote: false,
    provider_method: '',
    idp_signing_certificate: '',
    sso_binding_type: '',
    force_reauthentication: false,
    enable_debug_mode: false,
    advancedConfigurations: [],
  };

  const mergedInitialValues: SAMLCreationValues = {
    ...defaultValues,
    ...initialValues,
    advancedConfigurations: initialValues?.advancedConfigurations ?? defaultValues.advancedConfigurations,
  };

  return (
    <Formik
      initialValues={mergedInitialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="private_key"
            label={t_i18n('Private key')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            type="checkbox"
            name="want_assertions_signed"
            label={t_i18n('Want assertion signed')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            type="checkbox"
            name="want_auth_response_signed"
            label={t_i18n('Requires SAML responses to be signed')}
            containerstyle={{ marginLeft: 2 }}
          />
          <div style={{ marginTop: 40, marginBottom: 20 }}>
            <Typography variant="h2">Identity Provider Information</Typography>
            <Field
              component={SwitchField}
              variant="standard"
              type="checkbox"
              name="login_idp_directly"
              label={t_i18n('Allow login from identity provider directly')}
              containerstyle={{ marginLeft: 2 }}
            />
            <Field
              component={SwitchField}
              variant="standard"
              type="checkbox"
              name="logout_remote"
              label={t_i18n('Allow logout from Identity provider directly')}
              containerstyle={{ marginLeft: 2 }}
            />
          </div>
          <Field
            component={SelectField}
            variant="standard"
            name="provider_method"
            label={t_i18n('Method of Provider metadata')}
            fullWidth
            containerstyle={{ width: '100%' }}
          >
            <MenuItem value="Manual">Manual</MenuItem>
            <MenuItem value="Upload">Upload</MenuItem>
          </Field>
          <Field
            component={TextField}
            variant="standard"
            name="entity_id"
            label={t_i18n('SAML Entity ID/Issuer')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="saml_callback_url"
            label={t_i18n('SAML SSO URL')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            id="filled-multiline-flexible"
            component={TextField}
            variant="standard"
            name="idp_signing_certificate"
            label={t_i18n('Identity Provider Signing Certificate')}
            fullWidth
            multiline
            rows={4}
            style={{ marginTop: 20 }}
          />
          <Field
            id="filled-multiline-flexible"
            component={TextField}
            variant="standard"
            name="idp_cert"
            label={t_i18n('Identity Provider Encryption Certificate')}
            fullWidth
            multiline
            rows={4}
            style={{ marginTop: 20 }}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="sso_binding_type"
            label={t_i18n('SSO Binding type')}
            fullWidth
            containerstyle={{ width: '100%' }}
          >
            <MenuItem value="Redirect">Redirect</MenuItem>
            <MenuItem value="Post">Post</MenuItem>
          </Field>
          <Field
            component={SwitchField}
            variant="standard"
            type="checkbox"
            name="force_reauthentication"
            defaultValue={true}
            label={t_i18n('Force re-authentication even if user has valid SSO session')}
            containerstyle={{ marginLeft: 2 }}
          />
          {/* <Field */}
          {/*  component={SwitchField} */}
          {/*  variant="standard" */}
          {/*  type="checkbox" */}
          {/*  name="enable_debug_mode" */}
          {/*  label={t_i18n('Enable debug mode to troubleshoot for this authentication')} */}
          {/*  containerstyle={{ marginLeft: 2 }} */}
          {/* /> */}
          {/* <div style={{ marginTop: 40, marginBottom: 20 }}> */}
          {/*  <Typography variant="h2">OpenCTI Information</Typography> */}
          {/*  <Field */}
          {/*    component={TextField} */}
          {/*    variant="standard" */}
          {/*    name="metadata-url" */}
          {/*    label={t_i18n('Metadata URL')} */}
          {/*    fullWidth */}
          {/*    style={{ marginTop: 20 }} */}
          {/*  /> */}
          {/*  <Field */}
          {/*    component={TextField} */}
          {/*    variant="standard" */}
          {/*    name="entityID" */}
          {/*    label={t_i18n('Entity ID')} */}
          {/*    fullWidth */}
          {/*    style={{ marginTop: 20 }} */}
          {/*  /> */}
          {/*  <Field */}
          {/*    component={TextField} */}
          {/*    variant="standard" */}
          {/*    name="assertionConsummer" */}
          {/*    label={t_i18n('Assertion consummer')} */}
          {/*    fullWidth */}
          {/*    style={{ marginTop: 20 }} */}
          {/*  /> */}
          {/*  <Field */}
          {/*    id="filled-multiline-flexible" */}
          {/*    component={TextField} */}
          {/*    variant="standard" */}
          {/*    name="request" */}
          {/*    label={t_i18n('Authenticate request signing certificate')} */}
          {/*    fullWidth */}
          {/*    multiline */}
          {/*    rows={4} */}
          {/*    style={{ marginTop: 20 }} */}
          {/*  /> */}
          {/* </div> */}
          <FieldArray name="advancedConfigurations">
            {({ push, remove, form }) => (
              <>
                <div style={{ display: 'flex', alignItems: 'center' }}>
                  <Typography variant="h2">Add more fields</Typography>
                  <IconButton
                    color="secondary"
                    aria-label="Add"
                    size="large"
                    style={{ marginBottom: 12 }}
                    onClick={() =>
                      push({ key: '', value: '', type: 'String' }) // onAddField
                    }
                  >
                    <Add fontSize="small" />
                  </IconButton>
                </div>
                {form.values.advancedConfigurations
                  && form.values.advancedConfigurations.map(
                    (conf: { key: string; value: string; type: string }, index: number) => (
                      <div
                        key={index}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-around',
                          marginBottom: 8,
                        }}
                      >
                        <Field
                          component={TextField}
                          variant="standard"
                          name={`advancedConfigurations[${index}].key`}
                          label={t_i18n('Key (in passport)')}
                          containerstyle={{ width: '20%' }}
                        />
                        <Field
                          component={TextField}
                          variant="standard"
                          name={`advancedConfigurations[${index}].value`}
                          label={t_i18n('Value (in IDP)')}
                          containerstyle={{ width: '20%' }}
                        />
                        <Field
                          component={SelectField}
                          variant="standard"
                          name={`advancedConfigurations[${index}].type`}
                          label={t_i18n('Field type')}
                          containerstyle={{ width: '20%' }}
                        >
                          <MenuItem value="Boolean">Boolean</MenuItem>
                          <MenuItem value="Integer">Integer</MenuItem>
                          <MenuItem value="String">String</MenuItem>
                          <MenuItem value="Array">Array</MenuItem>
                        </Field>
                        <IconButton
                          color="primary"
                          aria-label={t_i18n('Delete')}
                          style={{ marginTop: 10 }}
                          onClick={() => remove(index)} // Delete
                        >
                          <Delete fontSize="small" />
                        </IconButton>
                      </div>
                    ),
                  )}
              </>
            )}
          </FieldArray>
          <div
            style={{
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
  );
};

export default SAMLCreation;
