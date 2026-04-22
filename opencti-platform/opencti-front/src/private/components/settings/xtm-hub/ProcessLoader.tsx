import React, { FunctionComponent } from 'react';
import { Box } from '@mui/material';
import Button from '@common/button/Button';
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
        height: '100%',
        minHeight: 100,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1,
      }}
    >
      <Loader variant={LoaderVariant.inElement} />
      <Button sx={{ marginTop: 4 }} onClick={onFocusTab}>
        {buttonText}
      </Button>
    </Box>
  );
};

export default ProcessLoader;
