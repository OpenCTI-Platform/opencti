import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';

interface ProcessSuccessProps {
  message: string;
  onClose: () => void;
}

const ProcessSuccess: FunctionComponent<ProcessSuccessProps> = ({
  message,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Box
      sx={{ display: 'flex', alignItems: 'center', flexDirection: 'column' }}
    >
      <div>{message}</div>
      <Button sx={{ marginTop: 4 }} variant="contained" onClick={onClose}>
        {t_i18n('Close')}
      </Button>
    </Box>
  );
};

export default ProcessSuccess;
