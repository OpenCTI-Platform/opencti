import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';

interface EnrollmentInstructionsProps {
  onContinue: () => void;
}

const EnrollmentInstructions: FunctionComponent<EnrollmentInstructionsProps> = ({
  onContinue,
}) => {
  const { t_i18n } = useFormatter();
  return <Box sx={{ display: 'flex', alignItems: 'center', flexDirection: 'column' }}>
    <p>{t_i18n('enrollment_instruction_paragraph')}</p>
    <div>
      <Button variant="contained" onClick={onContinue}>
        {t_i18n('Continue')}
      </Button>
    </div>
  </Box>;
};

export default EnrollmentInstructions;
