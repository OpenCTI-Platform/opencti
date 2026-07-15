import { Button, Divider } from '@mui/material';
import Bookmarks from '@mui/icons-material/Bookmarks';
import Tooltip from '@mui/material/Tooltip/Tooltip';
import React from 'react';
import { useFormatter } from '../../components/i18n';

interface WidgetSavedFiltersIconProps {
  onClick: () => void;
}

const WidgetSavedFiltersIcon = ({ onClick }: WidgetSavedFiltersIconProps) => {
  const { t_i18n } = useFormatter();
  return (
    <>
      <Divider orientation="vertical" flexItem />
      <Tooltip title={t_i18n('Use a saved filter')}>
        <Button
          size="small"
          onClick={onClick}
          sx={{ minWidth: 'unset', padding: '4px' }}
        >
          <Bookmarks fontSize="small" />
        </Button>
      </Tooltip>
    </>
  );
};

export default WidgetSavedFiltersIcon;
