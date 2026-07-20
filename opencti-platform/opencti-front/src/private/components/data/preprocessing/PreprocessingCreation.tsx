import React, { FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { AddOutlined } from '@mui/icons-material';
import Drawer from '../../common/drawer/Drawer';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { createRule } from './preprocessingStore';

interface PreprocessingCreationProps { onCreated?: () => void; }
interface CreationForm { name: string; description: string; }

const PreprocessingCreation: FunctionComponent<PreprocessingCreationProps> = ({ onCreated }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const validation = Yup.object().shape({ name: Yup.string().required(t_i18n('This field is required')), description: Yup.string().nullable() });
  const initialValues: CreationForm = { name: '', description: '' };
  return (
    <>
      <Button variant="contained" color="secondary" startIcon={<AddOutlined />} onClick={() => setOpen(true)}>
        {t_i18n('Create a rule')}
      </Button>
      <Drawer title={t_i18n('Create a pre-processing rule')} open={open} onClose={() => setOpen(false)}>
        {({ onClose }) => (
          <Formik<CreationForm>
            initialValues={initialValues}
            validationSchema={validation}
            onReset={onClose}
            onSubmit={(values, { setSubmitting, resetForm }) => {
              const rule = createRule(values.name, values.description);
              resetForm(); setSubmitting(false); onClose(); onCreated?.();
              navigate(`/dashboard/data/preprocessing/${rule.id}`);
            }}
          >
            {({ submitForm, handleReset, isSubmitting }) => (
              <Form>
                <Field component={TextField} variant="standard" name="name" label={t_i18n('Name')} fullWidth />
                <Field component={TextField} variant="standard" name="description" label={t_i18n('Description')} style={fieldSpacingContainerStyle} fullWidth />
                <FormButtonContainer>
                  <Button variant="outlined" onClick={handleReset} disabled={isSubmitting}>{t_i18n('Cancel')}</Button>
                  <Button variant="contained" color="secondary" onClick={submitForm} disabled={isSubmitting}>{t_i18n('Create')}</Button>
                </FormButtonContainer>
              </Form>
            )}
          </Formik>
        )}
      </Drawer>
    </>
  );
};
export default PreprocessingCreation;
