import { IconButton } from '@filigran/design-system';
import Tooltip from '@mui/material/Tooltip';
import { FilterList } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from 'src/components/i18n';

interface WidgetCustomFiltersIconProps {
  onClick: () => void;
}

const WidgetCustomFiltersIcon = ({ onClick }: WidgetCustomFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip title={t_i18n('Set custom filters')}>
      <IconButton
        variant="default"
        priority="tertiary"
        size="sm"
        aria-label={t_i18n('Set custom filters')}
        onClick={onClick}
        icon={<FilterList fontSize="small" />}
      />
    </Tooltip>
  );
};

export default WidgetCustomFiltersIcon;
