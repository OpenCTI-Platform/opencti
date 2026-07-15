import IconButton from '@common/button/IconButton';
import { FilterAltOff } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import { useFormatter } from 'src/components/i18n';

interface ClearFiltersIconProps {
  hasActiveFilters?: boolean;
  handleClearFilters: () => void;
  disabled?: boolean;
  color?: string;
}

const ClearFiltersIcon = ({
  hasActiveFilters,
  handleClearFilters,
  disabled = undefined,
  color,
}: ClearFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  const buttonColor = color ?? (hasActiveFilters ? 'primary' : 'default');
  return (
    <Tooltip title={t_i18n('Clear filters')}>
      <IconButton
        color={buttonColor}
        onClick={handleClearFilters}
        size="small"
        disabled={disabled != undefined ? disabled : !hasActiveFilters}
      >
        <FilterAltOff fontSize="small" />
      </IconButton>
    </Tooltip>
  );
};

export default ClearFiltersIcon;
