import { Field, Form, Formik } from 'formik';
import React from 'react';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import InputAdornment from '@mui/material/InputAdornment';
import Button from '@mui/material/Button';
import { Option } from '@components/common/form/ReferenceField';
import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { useFormatter } from '../../../components/i18n';
import TextField from '../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../utils/field';

export interface WorkspaceShareFormData {
  name: string;
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
    max_markings: Yup.array().min(1, 'This field is required').required(t_i18n('This field is required')),
  });

  return (
    <Formik<WorkspaceShareFormData>
      enableReinitialize={true}
      validationSchema={formValidation}
      initialValues={{
        name: '',
        uri_key: '',
        max_markings: [],
      }}
      onSubmit={onSubmit}
    >
      {({ isSubmitting, isValid, dirty, handleReset, submitForm }) => (
        <Form>
          <Field
            name="name"
            component={TextField}
            variant="standard"
            label={t_i18n('Name')}
            style={{ width: '100%' }}
          />
          <Field
            disabled
            name="uri_key"
            component={TextField}
            variant="standard"
            label={t_i18n('Public dashboard ID')}
            helperText={t_i18n('Specify the ID of your public dashboard')}
            style={fieldSpacingContainerStyle}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  public/dashboard/
                </InputAdornment>
              ),
            }}
          />
          <ObjectMarkingField
            name='max_markings'
            label={t_i18n('Max level markings')}
            helpertext={t_i18n('To prevent people seeing all the data...')}
            style={fieldSpacingContainerStyle}
          />

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
