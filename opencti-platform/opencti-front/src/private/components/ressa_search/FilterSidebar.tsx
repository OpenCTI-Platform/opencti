import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  TextField,
  InputAdornment,
  Checkbox,
  FormControlLabel,
  Collapse,
  IconButton,
  Divider,
} from '@mui/material';
import {
  Search,
  ExpandLess,
  ExpandMore,
} from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';

export interface FilterValue {
  key: string;
  value: string;
  checked: boolean;
}

export interface FilterGroup {
  key: string;
  label: string;
  values: FilterValue[];
  expanded: boolean;
}

interface FilterSidebarProps {
  filters: FilterGroup[];
  onFilterChange?: (filterKey: string, value: string, checked: boolean) => void;
}

const FilterSidebar = ({ filters, onFilterChange }: FilterSidebarProps) => {
  const { t_i18n } = useFormatter();
  const [filterSearch, setFilterSearch] = useState('');
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(
    filters.reduce((acc, filter) => {
      acc[filter.key] = filter.expanded;
      return acc;
    }, {} as Record<string, boolean>)
  );

  const handleToggleGroup = (filterKey: string) => {
    setExpandedGroups((prev) => ({
      ...prev,
      [filterKey]: !prev[filterKey],
    }));
  };

  const handleFilterToggle = (filterKey: string, value: string, checked: boolean) => {
    if (onFilterChange) {
      onFilterChange(filterKey, value, checked);
    }
  };

  const getFilterLabel = (key: string): string => {
    const labelMap: Record<string, string> = {
      actor: 'Attacker',
      cve: 'Vulnerability',
      country: 'Country',
      entity_type: 'Entity Type',
      last_seen: 'Last Seen',
      exploit_available: 'Exploit Available',
      exploit_in_the_wild: 'Exploit In The Wild',
    };
    return labelMap[key] || key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ');
  };

  const filteredFilters = filters.filter((filter) =>
    filterSearch === '' ||
    getFilterLabel(filter.key).toLowerCase().includes(filterSearch.toLowerCase()) ||
    filter.values.some((v) => v.value.toLowerCase().includes(filterSearch.toLowerCase()))
  );

  return (
    <Paper
      sx={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        borderRadius: 1,
        border: '1px solid',
        borderColor: 'divider',
        backgroundColor: 'background.paper',
        minHeight: 0,
        overflow: 'hidden',
      }}
    >
      <Box sx={{ padding: 2, borderBottom: '1px solid', borderColor: 'divider' }}>
        <Typography
          variant="h6"
          sx={{
            fontWeight: 600,
            marginBottom: 2,
          }}
        >
          {t_i18n('Filters')}
        </Typography>
        <TextField
          fullWidth
          size="small"
          variant="outlined"
          placeholder={t_i18n('Search filters')}
          value={filterSearch}
          onChange={(e) => setFilterSearch(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <Search fontSize="small" sx={{ color: 'text.secondary' }} />
              </InputAdornment>
            ),
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              backgroundColor: 'background.default',
            },
          }}
        />
      </Box>

      <Box
        sx={{
          flex: 1,
          overflowY: 'auto',
          padding: 2,
        }}
      >
        {filteredFilters.length === 0 ? (
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', mt: 2 }}>
            {t_i18n('No filters found')}
          </Typography>
        ) : (
          filteredFilters.map((filter, index) => (
            <Box key={filter.key}>
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                  paddingY: 1,
                  '&:hover': {
                    backgroundColor: 'action.hover',
                    borderRadius: 1,
                  },
                }}
                onClick={() => handleToggleGroup(filter.key)}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleGroup(filter.key);
                    }}
                    sx={{ padding: 0.5 }}
                  >
                    {expandedGroups[filter.key] ? (
                      <ExpandLess fontSize="small" />
                    ) : (
                      <ExpandMore fontSize="small" />
                    )}
                  </IconButton>
                  <Typography variant="subtitle2" sx={{ fontWeight: 500 }}>
                    {getFilterLabel(filter.key)}
                  </Typography>
                  <Typography
                    variant="caption"
                    sx={{
                      color: 'text.secondary',
                      marginLeft: 1,
                    }}
                  >
                    {filter.values.length}
                  </Typography>
                </Box>
              </Box>

              <Collapse in={expandedGroups[filter.key]}>
                <Box sx={{ paddingLeft: 3, paddingY: 1 }}>
                  {filter.values.length > 0 && (
                    <FormControlLabel
                      control={
                        <Checkbox
                          size="small"
                          checked={filter.values.every((v) => v.checked)}
                          indeterminate={
                            filter.values.some((v) => v.checked) &&
                            !filter.values.every((v) => v.checked)
                          }
                          onChange={(e) => {
                            filter.values.forEach((v) => {
                              handleFilterToggle(filter.key, v.value, e.target.checked);
                            });
                          }}
                          sx={{
                            padding: 0.5,
                            '&.Mui-checked': {
                              color: 'primary.main',
                            },
                          }}
                        />
                      }
                      label={
                        <Typography variant="caption" sx={{ fontSize: '0.75rem' }}>
                          {t_i18n('Select All')}
                        </Typography>
                      }
                      sx={{ marginBottom: 0.5 }}
                    />
                  )}
                  {filter.values.map((value, valueIndex) => (
                    <FormControlLabel
                      key={valueIndex}
                      control={
                        <Checkbox
                          size="small"
                          checked={value.checked}
                          onChange={(e) =>
                            handleFilterToggle(filter.key, value.value, e.target.checked)
                          }
                          sx={{
                            padding: 0.5,
                            '&.Mui-checked': {
                              color: 'primary.main',
                            },
                          }}
                        />
                      }
                      label={
                        <Typography variant="body2" sx={{ fontSize: '0.875rem' }}>
                          {value.value}
                        </Typography>
                      }
                      sx={{
                        display: 'flex',
                        marginLeft: 0,
                        marginBottom: 0.5,
                      }}
                    />
                  ))}
                </Box>
              </Collapse>
              {index < filteredFilters.length - 1 && (
                <Divider sx={{ marginY: 1 }} />
              )}
            </Box>
          ))
        )}
      </Box>
    </Paper>
  );
};

export default FilterSidebar;
