import { IconButton } from '@filigran/design-system';
import Bookmarks from '@mui/icons-material/Bookmarks';
import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import { useFormatter } from '../../components/i18n';

interface WidgetSavedFiltersIconProps {
  onClick: () => void;
  disabled?: boolean;
}

const WidgetSavedFiltersIcon = ({
  onClick,
  disabled = false,
}: WidgetSavedFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Tooltip
      title={disabled
        ? t_i18n('No saved filters compatible with this perspective')
        : t_i18n('Use a saved filter')}
    >
      <span>
        <IconButton
          variant="default"
          priority="tertiary"
          size="md"
          aria-label={t_i18n('Use a saved filter')}
          onClick={onClick}
          disabled={disabled}
          icon={<Bookmarks fontSize="small" />}
        />
      </span>
    </Tooltip>
  );
};

export default WidgetSavedFiltersIcon;
