import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';

interface EnrollmentLoaderProps {
  onFocusTab: () => void;
}

const EnrollmentLoader: FunctionComponent<EnrollmentLoaderProps> = ({
  onFocusTab,
}) => {
  const { t_i18n } = useFormatter();
  return <Box sx={{ position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    zIndex: 1 }}
         >
    <Loader variant={LoaderVariant.inElement} />
    <Button sx={{ marginTop: 4 }} variant="contained" onClick={onFocusTab}>
      {t_i18n('Continue to enroll')}
    </Button>
  </Box>;
};

export default EnrollmentLoader;
