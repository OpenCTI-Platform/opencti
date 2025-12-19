import { FormikConfig } from 'formik/dist/types';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import { Dialog, DialogTitle, DialogContent, MenuItem, DialogActions } from '@mui/material';
import Button from '@common/button/Button';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import React from 'react';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';

export interface CreateFileFormInputs {
  name: string;
  type: string;
  fileMarkings: FieldOption[];
}

interface CreateFileFormProps {
  isOpen: boolean;
  onClose: () => void;
  onReset: () => void;
  onSubmit: FormikConfig<CreateFileFormInputs>['onSubmit'];
}

const CreateFileForm = ({ isOpen, onClose, onReset, onSubmit }: CreateFileFormProps) => {
  const { t_i18n } = useFormatter();

  const validation = () => Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
  });

  const initialValues: CreateFileFormInputs = {
    name: '',
    type: 'text/html',
    fileMarkings: [],
  };

  return (
    <Formik<CreateFileFormInputs>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={validation}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            slotProps={{ paper: { elevation: 1 } }}
            open={isOpen}
            onClose={onClose}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Create a file')}</DialogTitle>
            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={SelectField}
                variant="standard"
                name="type"
                label={t_i18n('Type')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                <MenuItem value="text/html">{t_i18n('HTML')}</MenuItem>
                <MenuItem value="text/markdown">{t_i18n('Markdown')}</MenuItem>
                <MenuItem value="text/plain">{t_i18n('Text')}</MenuItem>
              </Field>
              <ObjectMarkingField
                label={t_i18n('File marking definition levels')}
                name="fileMarkings"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
            </DialogContent>
            <DialogActions>
              <Button variant="secondary" onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
              >
                {t_i18n('Create')}
              </Button>
            </DialogActions>
          </Dialog>
        </Form>
      )}
    </Formik>
  );
};

export default CreateFileForm;
