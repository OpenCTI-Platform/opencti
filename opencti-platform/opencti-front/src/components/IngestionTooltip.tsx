import { InfoOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import { isEmptyField } from '../utils/utils';

interface IngestionTooltipProps {
  children: React.ReactNode,
  logs: readonly string[]
}

const IngestionTooltip = ({ children, logs }: IngestionTooltipProps) => {
  return <Tooltip slotProps={{
    tooltip: {
      sx: {
        maxWidth: 'none',
        minWidth: '400px',
        overflow: 'auto',
      },
    },
  }} title={<pre>{isEmptyField(logs) ? 'No information yet' : logs.join('\r\n')}</pre>}
         >
    <div>
      <InfoOutlined fontSize="inherit" />
      <span style={{ marginLeft: 8 }}>{children}</span>
    </div>
  </Tooltip>;
};

export default IngestionTooltip;
