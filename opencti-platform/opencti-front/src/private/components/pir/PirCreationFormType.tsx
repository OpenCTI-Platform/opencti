import { Button } from '@mui/material';
import React from 'react';
import { useFormikContext } from 'formik';
import { useFormatter } from '../../../components/i18n';

const PirCreationFormType = () => {
  const { t_i18n } = useFormatter();
  const { setFieldValue } = useFormikContext();

  return (
    <div>
      <Button onClick={() => setFieldValue('type', 'threat-landscape')}>
        {t_i18n('Threat landscape')}
      </Button>
      <Button disabled>
        {t_i18n('Threat origin (coming soon)')}
      </Button>
    </div>
  );
};

export default PirCreationFormType;
