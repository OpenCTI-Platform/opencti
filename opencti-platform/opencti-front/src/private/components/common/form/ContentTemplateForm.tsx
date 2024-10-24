import { Field, Form, Formik } from 'formik';
import { Dialog, DialogTitle, DialogContent, DialogActions, Button, MenuItem } from '@mui/material';
import ObjectMarkingField from '@components/common/form/ObjectMarkingField';
import React from 'react';
import * as Yup from 'yup';
import { Option } from '@components/common/form/ReferenceField';
import { FormikConfig } from 'formik/dist/types';
import TextField from '../../../../components/TextField';
import AutocompleteField from '../../../../components/AutocompleteField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import type { Template } from '../../../../utils/outcome_template/template';

export interface ContentTemplateFormInputs {
  name: string
  template: Option | null
  type: string
  fileMarkings: Option[]
  maxMarkings: Option[]
}

interface ContentTemplateFormProps {
  isOpen: boolean
  onClose: () => void
  onReset: () => void
  onSubmit: FormikConfig<ContentTemplateFormInputs>['onSubmit']
  templates: Template[]
}

const ContentTemplateForm = ({
  isOpen,
  onClose,
  onReset,
  onSubmit,
  templates,
}: ContentTemplateFormProps) => {
  const { t_i18n } = useFormatter();

  const validation = () => Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    template: Yup.object().required(t_i18n('This field is required')),
    type: Yup.string().required(t_i18n('This field is required')),
  });

  const initialValues: ContentTemplateFormInputs = {
    name: '',
    template: null,
    type: 'text/html',
    fileMarkings: [],
    maxMarkings: [],
  };

  const templateOptions = templates.map((t) => ({
    value: t.id,
    label: t.name,
  }));

  return (
    <Formik<ContentTemplateFormInputs>
      enableReinitialize={true}
      initialValues={initialValues}
      validationSchema={validation}
      onSubmit={onSubmit}
      onReset={onReset}
    >
      {({ submitForm, handleReset, isSubmitting, setFieldValue }) => (
        <Form>
          <Dialog
            PaperProps={{ elevation: 1 }}
            open={isOpen}
            onClose={onClose}
            fullWidth={true}
          >
            <DialogTitle>{t_i18n('Create a content from a template')}</DialogTitle>
            <DialogContent>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Name')}
                fullWidth={true}
              />
              <Field
                component={AutocompleteField}
                name='template'
                fullWidth={true}
                style={fieldSpacingContainerStyle}
                options={templateOptions}
                renderOption={(
                  props: React.HTMLAttributes<HTMLLIElement>,
                  option: Option,
                ) => <li {...props}>{option.label}</li>}
                textfieldprops={{ label: t_i18n('Template') }}
                optionLength={80}
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
              </Field>
              <ObjectMarkingField
                label={t_i18n('File marking definition levels')}
                name="fileMarkings"
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
              />
              <ObjectMarkingField
                name='maxMarkings'
                label={t_i18n('Max content level markings')}
                helpertext={t_i18n('To prevent people seeing all the data, select a marking definition to restrict the data included in the outcome file.')}
                style={fieldSpacingContainerStyle}
                setFieldValue={setFieldValue}
                limitToMaxSharing
              />
            </DialogContent>
            <DialogActions>
              <Button onClick={handleReset} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button
                color="secondary"
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

export default ContentTemplateForm;
