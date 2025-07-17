import React, { FunctionComponent } from 'react';
import { Box, Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';

interface EnrollmentSuccessProps {
  closeDialog: () => void;
}
const EnrollmentSuccess: FunctionComponent<EnrollmentSuccessProps> = ({ closeDialog }) => {
  const { t_i18n } = useFormatter();
  return <Box sx={{ display: 'flex', alignItems: 'center', flexDirection: 'column' }}>
    <div> {t_i18n('Success the enrollment of your OCTI is done')}</div>
    <Button sx={{ marginTop: 4 }} variant="contained" onClick={closeDialog}>
      {t_i18n('Close')}
    </Button>
  </Box>;
};

export default EnrollmentSuccess;
