import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface ProcessLoaderProps {
  onFocusTab: () => void;
  buttonText: string;
}

const ProcessLoader: FunctionComponent<ProcessLoaderProps> = ({
  onFocusTab,
  buttonText,
}) => {
  return (
    <Box
      sx={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%)',
        zIndex: 1,
      }}
    >
      <Loader variant={LoaderVariant.inElement} />
      <Button sx={{ marginTop: 4 }} variant="contained" onClick={onFocusTab}>
        {buttonText}
      </Button>
    </Box>
  );
};

export default ProcessLoader;
