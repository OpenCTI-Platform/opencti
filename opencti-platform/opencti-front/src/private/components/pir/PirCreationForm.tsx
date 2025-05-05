import { DialogTitle, DialogContent, Button, DialogActions } from '@mui/material';
import React, { useState } from 'react';
import { Form, Formik } from 'formik';
import PirCreationFormGeneralSettings from './PirCreationFormGeneralSettings';
import PirCreationFormType from './PirCreationFormType';
import PirCreationFormStepper from './PirCreationFormStepper';
import { useFormatter } from '../../../components/i18n';
import type { FieldOption } from '../../../utils/field';
import PirCreationFormCriteria from './PirCreationFormCriteria';

interface PirCreationFormData {
  type: string | null
  name: string | null
  description: string | null
  markings: FieldOption[]
  confidence: number | null
  // TODO PIR should have different defs depending of type
  locations: FieldOption[]
  sectors: FieldOption[]
}

interface PirCreationFormProps {
  onCancel: () => void
}

const PirCreationForm = ({ onCancel }: PirCreationFormProps) => {
  const { t_i18n } = useFormatter();
  const [step, setStep] = useState(0);

  const initialValues: PirCreationFormData = {
    type: null,
    name: null,
    description: null,
    markings: [],
    confidence: null,
    locations: [],
    sectors: [],
  };

  return (
    <Formik<PirCreationFormData>
      initialValues={initialValues}
      onSubmit={console.log}
    >
      {({ values, errors, isValid, submitForm }) => {
        const step0Valid = !!values.type;
        const step1Valid = (!!values.name && !errors.name)
          && (values.markings.length > 0 && !errors.markings);

        const isStepValid = (step === 0 && step0Valid)
          || (step === 1 && step1Valid)
          || (step === 2 && isValid);

        const accessibleSteps = [0];
        if (step0Valid) accessibleSteps.push(1);
        if (step1Valid) accessibleSteps.push(2);

        return (
          <>
            <DialogTitle>
              {t_i18n('Create priority intelligence requirement')}
            </DialogTitle>

            <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <PirCreationFormStepper
                step={step}
                accessibleSteps={accessibleSteps}
                onClickStep={setStep}
              />

              <Form>
                {step === 0 && <PirCreationFormType />}
                {step === 1 && <PirCreationFormGeneralSettings />}
                {step === 2 && <PirCreationFormCriteria />}
              </Form>
            </DialogContent>

            <DialogActions>
              <Button onClick={onCancel}>
                {t_i18n('Cancel')}
              </Button>
              {step !== 2 && (
                <Button
                  onClick={() => setStep(step + 1)}
                  color="secondary"
                  disabled={!isStepValid}
                >
                  {t_i18n('Next')}
                </Button>
              )}
              {step === 2 && (
                <Button
                  onClick={submitForm}
                  color="secondary"
                  disabled={!isStepValid}
                >
                  {t_i18n('Create')}
                </Button>
              )}
            </DialogActions>
          </>
        );
      }}
    </Formik>
  );
};

export default PirCreationForm;
