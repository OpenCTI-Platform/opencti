import React, { FunctionComponent } from 'react';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../i18n';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface QuickRelativeDateFiltersButtonsProps {
  filter?: Filter;
  helpers?: handleFilterHelpers;
  handleClose: () => void;
}

const QuickRelativeDateFiltersButtons: FunctionComponent<QuickRelativeDateFiltersButtonsProps> = ({
  filter,
  helpers,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const quickButtons = [
    { label: t_i18n('Last 30 minutes'), value: 'now-30m' },
    { label: t_i18n('Last 1 hour'), value: 'now-1h' },
    { label: t_i18n('Last 12 hours'), value: 'now-12h' },
    { label: t_i18n('Last 1 day'), value: 'now-1d' },
    { label: t_i18n('Last 6 months'), value: 'now-6M' },
    { label: t_i18n('Last 1 year'), value: 'now-1y' },
  ];
  const handleClick = (value: string) => {
    helpers?.handleReplaceFilterValues(filter?.id ?? '', [value, 'now']);
    handleClose();
  };
  return (
    <div style={{ marginLeft: 20 }}>
      {quickButtons.map((button) => (
        <Button
          key={button.value}
          size="small"
          style={{
            textTransform: 'none',
            color: theme.palette.text.primary,
          }}
          onClick={() => handleClick(button.value)}
        >
          {button.label}
        </Button>
      ))}
    </div>
  );
};

export default QuickRelativeDateFiltersButtons;
