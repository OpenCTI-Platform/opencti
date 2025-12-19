import React, { FunctionComponent } from 'react';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
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
      <p style={{ whiteSpace: 'pre-line', width: '100%' }}>
        {t_i18n(instructionKey)}
      </p>
      <div style={{ display: 'flex', justifyContent: 'flex-end', width: '100%' }}>
        <Button onClick={onContinue}>
          {t_i18n('Continue')}
        </Button>
      </div>
    </Box>
  );
};

export default ProcessInstructions;
