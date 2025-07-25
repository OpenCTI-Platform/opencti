import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';

interface ProcessInstructionsProps {
  onContinue: () => void;
  instructionKey: string;
}

const ProcessInstructions: FunctionComponent<ProcessInstructionsProps> = ({
  onContinue,
  instructionKey,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Box
      sx={{ display: 'flex', alignItems: 'center', flexDirection: 'column' }}
    >
      <p style={{ whiteSpace: 'pre-line', textAlign: 'center' }}>
        {t_i18n(instructionKey)}
      </p>
      <div>
        <Button variant="contained" onClick={onContinue}>
          {t_i18n('Continue')}
        </Button>
      </div>
    </Box>
  );
};

export default ProcessInstructions;
