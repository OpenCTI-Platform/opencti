import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Button, IconButton } from '@mui/material';
import { TextField } from 'formik-mui';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import { Add, Delete } from '@mui/icons-material';
import Typography from '@mui/material/Typography';

export interface SAMLCreationValues {
  name: string;
  enabled: boolean;
  entityId: string;
  ssoUrl: string;
}

interface SAMLCreationProps {
  initialValues?: Partial<SAMLCreationValues>;
  onSubmit: (values: SAMLCreationValues, helpers: { setSubmitting: (b: boolean) => void; resetForm: () => void }) => void;
  onCancel: () => void;
}

const SAMLCreation: FunctionComponent<SAMLCreationProps> = ({
  initialValues,
  onSubmit,
  onCancel,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    entityId: Yup.string().required(t_i18n('This field is required')),
    ssoUrl: Yup.string().url(t_i18n('Must be a valid URL')).required(t_i18n('This field is required')),
  });

  const defaultValues: SAMLCreationValues = {
    name: '',
    enabled: true,
    entityId: '',
    ssoUrl: '',
  };

  const mergedInitialValues: SAMLCreationValues = {
    ...defaultValues,
    ...initialValues,
  };

  return (
    <Formik
      initialValues={mergedInitialValues}
      validationSchema={validationSchema}
      onSubmit={(values, helpers) => onSubmit(values, helpers)}
      onReset={onCancel}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Authentication Name')}
            fullWidth
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="enabled"
            defaultValue={true}
            label={t_i18n('Enable SAML authentication')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="private"
            label={t_i18n('Private key')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="assertion"
            defaultValue={true}
            label={t_i18n('Want assertion signed')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="responses"
            defaultValue={true}
            label={t_i18n('Requires SAML responses to be signed')}
            containerstyle={{ marginLeft: 2 }}
          />
          <div style={{ marginTop: 40, marginBottom: 20 }}>
            <Typography variant="h2">Identity Provider Information</Typography>
            <Field
              component={SwitchField}
              variant="standard"
              name="login"
              defaultValue={true}
              label={t_i18n('Allow login from identity provider directly')}
              containerstyle={{ marginLeft: 2 }}
            />
            <Field
              component={SwitchField}
              variant="standard"
              name="responses"
              defaultValue={true}
              label={t_i18n('Allow logout from Identity provider directly')}
              containerstyle={{ marginLeft: 2 }}
            />
          </div>
          <Field
            component={SelectField}
            variant="standard"
            name="entityId"
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
            name="entityId"
            label={t_i18n('SAML Entity ID')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="ssoUrl"
            label={t_i18n('SAML SSO URL')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            id="filled-multiline-flexible"
            component={TextField}
            variant="standard"
            name="entityId"
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
            name="entityId"
            label={t_i18n('Identity Provider Encryption Certificate')}
            fullWidth
            multiline
            rows={4}
            style={{ marginTop: 20 }}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="entityId"
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
            name="login"
            defaultValue={true}
            label={t_i18n('Force Authentication even if user has valid SSO session')}
            containerstyle={{ marginLeft: 2 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="login"
            defaultValue={true}
            label={t_i18n('Enable debug mode to troubleshoot for this authentication')}
            containerstyle={{ marginLeft: 2 }}
          />
          <div style={{ marginTop: 40, marginBottom: 20 }}>
            <Typography variant="h2">OpenCTI Information</Typography>
            <Field
              component={TextField}
              variant="standard"
              name="metadata url"
              label={t_i18n('Metadata URL')}
              fullWidth
              style={{ marginTop: 20 }}
            />
            <Field
              component={TextField}
              variant="standard"
              name="entityID"
              label={t_i18n('Entity ID')}
              fullWidth
              style={{ marginTop: 20 }}
            />
            <Field
              component={TextField}
              variant="standard"
              name="assertionConsummer"
              label={t_i18n('Assertion consummer')}
              fullWidth
              style={{ marginTop: 20 }}
            />
            <Field
              id="filled-multiline-flexible"
              component={TextField}
              variant="standard"
              name="request"
              label={t_i18n('Authenticate request signing certificate')}
              fullWidth
              multiline
              rows={4}
              style={{ marginTop: 20 }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <Typography variant="h2">Add more fields</Typography>
            <IconButton
              color="secondary"
              aria-label="Add"
              // onClick={() =>
              // onAddField(setFieldValue, values)
              // }
              size="large"
              style={{ marginBottom: 12 }}
            >
              <Add fontSize="small" />
            </IconButton>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around' }}>
            <Field
              component={TextField}
              variant="standard"
              name="key"
              label={t_i18n('Key (in passport)')}
              containerstyle={{ width: '20%' }}
            />
            <Field
              component={TextField}
              variant="standard"
              name="value"
              label={t_i18n('Value (in IDP)')}
              containerstyle={{ width: '20%' }}
            />
            <Field
              component={SelectField}
              variant="standard"
              name="type"
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
              // onClick={() => onRemove?.()}
            >
              <Delete fontSize="small" />
            </IconButton>
          </div>
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
