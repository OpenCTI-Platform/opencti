import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { InfoOutlined } from '@mui/icons-material';
import { Stack } from '@mui/material';
import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../components/i18n';

const GenerateExportTitle: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  return (
    <Stack
      direction="row"
      sx={{
        alignItems: 'center',
        gap: 1,
      }}
    >
      {t_i18n('Generate an export')}
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoOutlined color="primary" sx={{ display: 'block' }} />
        </TooltipTrigger>
        <TooltipContent>
          {t_i18n('The content max markings can\'t exceed your max shareable markings. If none are selected, your max shareable markings are used. Entities above this limit are excluded from the export.')}
        </TooltipContent>
      </Tooltip>
    </Stack>
  );
};

export default GenerateExportTitle;
