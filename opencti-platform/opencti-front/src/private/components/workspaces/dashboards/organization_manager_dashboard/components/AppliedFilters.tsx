import React from 'react';
import {
  Box,
  Chip,
  IconButton,
  Typography,
} from '@mui/material';
import { Dismiss24Regular as CloseIcon } from '@fluentui/react-icons';
import { AppliedFilter } from './DashboardFilterBar';
import { useFormatter } from '../../../../../../components/i18n';

interface AppliedFiltersProps {
  filters: AppliedFilter[];
  onRemoveFilter: (key: string) => void;
  onClearAll: () => void;
}

const AppliedFilters: React.FC<AppliedFiltersProps> = ({
  filters,
  onRemoveFilter,
  onClearAll,
}) => {
  const { t_i18n } = useFormatter();

  if (filters.length === 0) {
    return null;
  }

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        flexWrap: 'wrap',
        flexDirection: 'row',
        backgroundColor: 'background.paper',
      }}
    >
      {/* Applied Filter Chips */}
      {filters.map((filter) => (
        <Chip
          key={filter.key}
          label={`${filter.label}: ${filter.value}`}
          onDelete={() => onRemoveFilter(filter.key)}
          deleteIcon={
            <IconButton size="small" sx={{ color: 'inherit' }}>
              <CloseIcon fontSize="small" />
            </IconButton>
          }
          sx={{
            backgroundColor: 'primary.lighter',
            color: 'primary.main',
            '& .MuiChip-deleteIcon': {
              color: 'primary.main',
              '&:hover': {
                color: 'primary.dark',
              },
            },
          }}
        />
      ))}

      {/* Clear All Filters Link - right aligned in LTR */}
      <Box
        onClick={onClearAll}
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          marginInlineStart: 'auto',
          color: 'error.main',
          cursor: 'pointer',
          flexDirection: 'row',
          '&:hover': {
            textDecoration: 'underline',
          },
        }}
      >
        <CloseIcon fontSize="small" />
        <Typography variant="body2" sx={{ fontWeight: 500 }}>
          {t_i18n('Remove filters')}
        </Typography>
      </Box>
    </Box>
  );
};

export default AppliedFilters;
