import React from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';
import { Box } from '@mui/material';

const MiddleManagersDashboard = () => {
  const { t_i18n } = useFormatter();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Middle Managers Dashboard'));

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Middle Managers Dashboard'), current: true },
        ]}
      />
      <Box sx={{ padding: 3 }}>
        {/* Dashboard content will be added in the future */}
      </Box>
    </>
  );
};

export default MiddleManagersDashboard;
