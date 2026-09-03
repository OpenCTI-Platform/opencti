import { InfoOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import Tooltip from '@mui/material/Tooltip';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../components/i18n';

const GenerateExportTitle: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  return (
    <Stack direction="row" alignItems="center" gap={1}>
      {t_i18n('Generate an export')}
      <Tooltip title={t_i18n('Your max shareable markings will be applied to the content max markings')}>
        <InfoOutlined color="primary" sx={{ display: 'block' }} />
      </Tooltip>
    </Stack>
  );
};

export default GenerateExportTitle;
