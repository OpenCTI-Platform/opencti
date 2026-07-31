import { Button } from '@mui/material';
import Bookmarks from '@mui/icons-material/Bookmarks';
import Tooltip from '@mui/material/Tooltip';
import React from 'react';
import { useFormatter } from '../../components/i18n';
import { WidgetPerspective } from 'src/utils/widget/widget';

interface WidgetSavedFiltersIconProps {
  onClick: () => void;
  perspective?: WidgetPerspective | null;
}

const WidgetSavedFiltersIcon = ({ onClick, perspective }: WidgetSavedFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  const disabled = perspective === 'audits';
  return (
    <Tooltip
      title={disabled
        ? t_i18n('No saved filters compatible with this perspective')
        : t_i18n('Use a saved filter')}
    >
      <span>
        <Button
          size="small"
          onClick={onClick}
          sx={{ minWidth: 'unset', padding: '4px' }}
          disabled={disabled}
        >
          <Bookmarks fontSize="small" />
        </Button>
      </span>
    </Tooltip>
  );
};

export default WidgetSavedFiltersIcon;
