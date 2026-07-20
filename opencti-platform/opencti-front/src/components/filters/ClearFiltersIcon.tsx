import IconButton from '@common/button/IconButton';
import { FilterAltOff } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import { useFormatter } from 'src/components/i18n';
import { ButtonColorKey } from '@common/button/Button.types';

interface ClearFiltersIconProps {
  hasActiveFilters?: boolean;
  onClear: () => void;
  disabled?: boolean;
  color?: ButtonColorKey;
}

const ClearFiltersIcon = ({
  hasActiveFilters,
  onClear,
  disabled,
  color,
}: ClearFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  const buttonColor = color ?? (hasActiveFilters ? 'primary' : 'default');
  return (
    <Tooltip title={t_i18n('Clear filters')}>
      <IconButton
        color={buttonColor}
        onClick={onClear}
        size="small"
        disabled={hasActiveFilters != undefined ? !hasActiveFilters : disabled}
      >
        <FilterAltOff fontSize="small" />
      </IconButton>
    </Tooltip>
  );
};

export default ClearFiltersIcon;
