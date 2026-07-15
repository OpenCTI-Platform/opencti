import { Button, Divider } from '@mui/material';
import Tooltip from '@mui/material/Tooltip/Tooltip';
import { FilterList } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from 'src/components/i18n';

interface WidgetCustomFiltersIconProps {
  onClick: () => void;
}

const WidgetCustomFiltersIcon = ({ onClick }: WidgetCustomFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      <Divider orientation="vertical" flexItem />
      <Tooltip title={t_i18n('Set custom filters')}>
        <Button
          size="small"
          sx={{ minWidth: 'unset', padding: '4px' }}
          onClick={onClick}
        >
          <FilterList fontSize="small" />
        </Button>
      </Tooltip>
    </>
  );
};

export default WidgetCustomFiltersIcon;
