/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { DialogActions, DialogContent, DialogTitle } from '@mui/material';
import React, { useState } from 'react';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import Button from '@common/button/Button';
import { PirCreationFormData } from './pir-form-utils';
import PirCreationFormGeneralSettings, { redisStreamQuery } from './PirCreationFormGeneralSettings';
import PirCreationFormStepper from './PirCreationFormStepper';
import { useFormatter } from '../../../../components/i18n';
import PirCreationFormCriteria from './PirCreationFormCriteria';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PirCreationFormGeneralSettingsRedisStreamQuery } from './__generated__/PirCreationFormGeneralSettingsRedisStreamQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface PirCreationFormProps {
  onCancel: () => void;
  onSubmit: (data: PirCreationFormData) => void;
}

const PirCreationForm = ({ onCancel, onSubmit }: PirCreationFormProps) => {
  const { t_i18n } = useFormatter();
  const [step, setStep] = useState(0);

  const redisQueryRef = useQueryLoading<PirCreationFormGeneralSettingsRedisStreamQuery>(redisStreamQuery);

  const validation = Yup.object().shape({
    pir_type: Yup.string().trim().required(t_i18n('This field is required')),
    name: Yup.string().trim().required(t_i18n('This field is required')),
    description: Yup.string().nullable(),
    pir_rescan_days: Yup.number().nullable().required(t_i18n('This field is required')),
    confidence: Yup.number().integer().required(t_i18n('This field is required')),
    locations: Yup.array().when('sectors', {
      is: (sectors: unknown[]) => sectors?.length === 0,
      then: (schema) => schema.min(1, t_i18n('At least 1 location or 1 sector is required')),
      otherwise: (schema) => schema.min(0),
    }),
    sectors: Yup.array().when('locations', {
      is: (locations: unknown[]) => locations?.length === 0,
      then: (schema) => schema.min(1, t_i18n('At least 1 location or 1 sector is required')),
      otherwise: (schema) => schema.min(0),
    }),
  }, [['sectors', 'locations']]);

  const initialValues: PirCreationFormData = {
    pir_type: 'THREAT_LANDSCAPE',
    name: '',
    description: '',
    pir_rescan_days: 30,
    confidence: 60,
    locations: [],
    sectors: [],
  };

  return (
    <Formik<PirCreationFormData>
      validationSchema={validation}
      initialValues={initialValues}
      onSubmit={onSubmit}
    >
      {({ values, errors, isValid, submitForm }) => {
        const step0Valid = (!!values.name && !errors.name)
          && (!errors.description)
          && ((!!values.pir_rescan_days || values.pir_rescan_days === 0) && !errors.pir_rescan_days);

        const isStepValid = (step === 0 && step0Valid) || (step === 1 && isValid);

        const accessibleSteps = [0];
        if (step0Valid) accessibleSteps.push(1);

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
                {step === 0 && (
                  <>
                    {redisQueryRef && (
                      <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                        <PirCreationFormGeneralSettings redisQueryRef={redisQueryRef} />
                      </React.Suspense>
                    )}
                  </>
                )}
                {step === 1 && <PirCreationFormCriteria />}
              </Form>
            </DialogContent>

            <DialogActions>
              <Button variant="secondary" onClick={onCancel}>
                {t_i18n('Cancel')}
              </Button>
              {step !== 1 && (
                <Button
                  onClick={() => setStep(step + 1)}
                  disabled={!isStepValid}
                >
                  {t_i18n('Next')}
                </Button>
              )}
              {step === 1 && (
                <Button
                  onClick={submitForm}
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
