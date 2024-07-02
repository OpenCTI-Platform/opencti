import { Field, Form, Formik } from 'formik';
import React from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import InputAdornment from '@mui/material/InputAdornment';
import Button from '@mui/material/Button';
import { Option } from '@components/common/form/ReferenceField';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import Alert from '@mui/material/Alert';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import SwitchField from '../../../components/fields/SwitchField';

export interface WorkspaceShareFormData {
  name: string;
  enabled: boolean;
  uri_key: string;
  max_markings: Option[];
}

interface WorkspaceShareFormProps {
  onSubmit: FormikConfig<WorkspaceShareFormData>['onSubmit']
}

const WorkspaceShareForm = ({ onSubmit }: WorkspaceShareFormProps) => {
  const { t_i18n } = useFormatter();

  const formValidation = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    uri_key: Yup.string(),
    enabled: Yup.boolean(),
    max_markings: Yup.array().min(1, 'This field is required').required(t_i18n('This field is required')),
  });

  return (
    <Formik<WorkspaceShareFormData>
      enableReinitialize={true}
      validationSchema={formValidation}
      initialValues={{
        name: '',
        enabled: true,
        uri_key: '',
        max_markings: [],
      }}
      onSubmit={onSubmit}
    >
      {({ isSubmitting, isValid, dirty, handleReset, submitForm, setFieldValue }) => (
        <Form>
          <Field
            name="name"
            component={TextField}
            variant="standard"
            label={t_i18n('Name')}
            style={{ width: '100%' }}
            onChange={(_: string, val: string) => {
              setFieldValue('uri_key', val.replace(/[^a-zA-Z0-9\s-]+/g, '').replace(/\s+/g, '-').toLowerCase());
            }}
          />
          <Field
            disabled
            name="uri_key"
            component={TextField}
            variant="standard"
            label={t_i18n('Public dashboard URI KEY')}
            helperText={t_i18n('ID of your public dashboard')}
            style={fieldSpacingContainerStyle}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  public/dashboard/
                </InputAdornment>
              ),
            }}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="enabled"
            label={t_i18n('Enabled')}
            containerstyle={fieldSpacingContainerStyle}
            helpertext={t_i18n('Disabled dashboard...')}
          />
          <ObjectMarkingField
            name='max_markings'
            label={t_i18n('Max level markings')}
            helpertext={t_i18n('To prevent people seeing all the data...')}
            style={fieldSpacingContainerStyle}
            onChange={() => {}}
            setFieldValue={setFieldValue}
            limitToMaxSharing
          />
          <Alert severity="info" variant="outlined" style={{ marginTop: '10px' }}>
            {t_i18n('You see only marking definitions that can be shared (defined by the admin)')}
          </Alert>

          <div
            style={{
              ...fieldSpacingContainerStyle,
              display: 'flex',
              justifyContent: 'end',
              gap: '12px',
            }}
          >
            <Button
              variant="contained"
              disabled={isSubmitting}
              onClick={handleReset}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              disabled={isSubmitting || !isValid || !dirty}
              onClick={submitForm}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default WorkspaceShareForm;
