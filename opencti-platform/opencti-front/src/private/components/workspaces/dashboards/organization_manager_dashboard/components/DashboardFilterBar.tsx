import React, { useRef, useState } from 'react';
import {
  Box,
  TextField,
  Button,
  InputAdornment,
  IconButton,
} from '@mui/material';
import {
  Search24Regular as SearchIcon,
  Filter24Regular as FilterIcon,
  Settings24Regular as SettingsIcon,
} from '@fluentui/react-icons';
import { useFormatter } from '../../../../../../components/i18n';
import FilterDropdown from './FilterDropdown';
import AppliedFilters from './AppliedFilters';

export interface FilterValue {
  id: string;
  label: string;
}

export interface AppliedFilter {
  key: string;
  label: string;
  value: string;
}

interface DashboardFilterBarProps {
  searchValue: string;
  onSearchChange: (value: string) => void;
  onSearch: () => void;
  appliedFilters: AppliedFilter[];
  onAppliedFiltersChange: (filters: AppliedFilter[]) => void;
  onPersonalizationClick?: () => void;
  onFiltersClick?: () => void;
}

const DashboardFilterBar: React.FC<DashboardFilterBarProps> = ({
  searchValue,
  onSearchChange,
  onSearch,
  appliedFilters,
  onAppliedFiltersChange,
  onPersonalizationClick,
  onFiltersClick,
}) => {
  const { t_i18n } = useFormatter();
  const inputRef = useRef<HTMLDivElement>(null);

  const [riskReductionStatus, setRiskReductionStatus] = useState<FilterValue | null>({
    id: 'excellent',
    label: 'Excellent',
  });
  const [confidenceLevel, setConfidenceLevel] = useState<FilterValue | null>({
    id: 'all_levels',
    label: 'All levels',
  });
  const [geographicalArea, setGeographicalArea] = useState<FilterValue | null>({
    id: 'iran',
    label: 'Iran',
  });
  const [section, setSection] = useState<FilterValue | null>({
    id: 'all_sections',
    label: 'All sections',
  });
  const [timeRange, setTimeRange] = useState<FilterValue | null>({
    id: 'last_3_months',
    label: 'Last 3 months',
  });

  const riskReductionStatusOptions: FilterValue[] = [
    { id: 'excellent', label: 'Excellent' },
    { id: 'good', label: 'Good' },
    { id: 'fair', label: 'Fair' },
    { id: 'poor', label: 'Poor' },
  ];

  const confidenceLevelOptions: FilterValue[] = [
    { id: 'all_levels', label: 'All levels' },
    { id: 'high', label: 'High' },
    { id: 'medium', label: 'Medium' },
    { id: 'low', label: 'Low' },
  ];

  const geographicalAreaOptions: FilterValue[] = [
    { id: 'iran', label: 'Iran' },
    { id: 'all', label: 'All' },
    { id: 'europe', label: 'Europe' },
    { id: 'asia', label: 'Asia' },
  ];

  const sectionOptions: FilterValue[] = [
    { id: 'all_sections', label: 'All sections' },
    { id: 'financial', label: 'Financial' },
    { id: 'energy', label: 'Energy' },
    { id: 'healthcare', label: 'Healthcare' },
  ];

  const timeRangeOptions: FilterValue[] = [
    { id: 'last_3_months', label: 'Last 3 months' },
    { id: 'last_month', label: 'Last month' },
    { id: 'last_week', label: 'Last week' },
    { id: 'last_year', label: 'Last year' },
  ];

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter') {
      onSearch();
    }
  };

  // Update applied filters when dropdown values change
  React.useEffect(() => {
    const newFilters: AppliedFilter[] = [];
    
    // Always show all filters (based on the design in the image)
    if (timeRange) {
      newFilters.push({
        key: 'time_range',
        label: 'Time Range',
        value: timeRange.label,
      });
    }
    if (section) {
      newFilters.push({
        key: 'section',
        label: 'Section',
        value: section.label,
      });
    }
    if (geographicalArea) {
      newFilters.push({
        key: 'geographical_area',
        label: 'Geographical Area',
        value: geographicalArea.label,
      });
    }
    if (confidenceLevel) {
      newFilters.push({
        key: 'confidence_level',
        label: 'Confidence Level',
        value: confidenceLevel.label,
      });
    }
    if (riskReductionStatus) {
      newFilters.push({
        key: 'risk_reduction_status',
        label: 'Risk Reduction Status',
        value: riskReductionStatus.label,
      });
    }

    onAppliedFiltersChange(newFilters);
  }, [riskReductionStatus, confidenceLevel, geographicalArea, section, timeRange, onAppliedFiltersChange]);

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        gap: 2,
        padding: 2,
        backgroundColor: 'background.paper',
        borderBottom: '1px solid',
        borderColor: 'divider',
      }}
    >
      {/* Top Filter Bar - LTR layout for English */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          flexWrap: 'wrap',
          flexDirection: 'row',
        }}
      >
        {/* Home Link - left aligned */}
        <Box
          sx={{
            marginRight: 'auto',
            color: 'text.secondary',
            fontWeight: 500,
            cursor: 'pointer',
            '&:hover': {
              color: 'primary.main',
            },
          }}
        >
          {t_i18n('Home')}
        </Box>

        {/* Filter Dropdowns */}
        <FilterDropdown
          label={timeRange?.label || 'Time Range'}
          value={timeRange}
          options={timeRangeOptions}
          onChange={setTimeRange}
        />
        <FilterDropdown
          label={section?.label || 'Section'}
          value={section}
          options={sectionOptions}
          onChange={setSection}
        />
        <FilterDropdown
          label={geographicalArea?.label || 'Geographical Area'}
          value={geographicalArea}
          options={geographicalAreaOptions}
          onChange={setGeographicalArea}
        />
        <FilterDropdown
          label={confidenceLevel?.label || 'Confidence Level'}
          value={confidenceLevel}
          options={confidenceLevelOptions}
          onChange={setConfidenceLevel}
        />
        <FilterDropdown
          label={riskReductionStatus?.label || 'Risk Reduction Status'}
          value={riskReductionStatus}
          options={riskReductionStatusOptions}
          onChange={setRiskReductionStatus}
        />

        {/* Search Field */}
        <Box sx={{ width: 300, maxWidth: '100%' }}>
          <TextField
            ref={inputRef}
            fullWidth
            variant="outlined"
            placeholder={t_i18n('Search phrase...')}
            value={searchValue}
            onChange={(e) => onSearchChange(e.target.value)}
            onKeyDown={handleKeyDown}
            size="small"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" style={{ color: 'inherit' }} />
                </InputAdornment>
              ),
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                backgroundColor: 'background.paper',
              },
            }}
          />
        </Box>

        {/* Filters Button */}
        <Button
          variant="outlined"
          startIcon={<FilterIcon />}
          onClick={onFiltersClick}
          sx={{
            textTransform: 'none',
            minWidth: 'auto',
            whiteSpace: 'nowrap',
            '& .MuiButton-startIcon': {
              marginRight: 0.5,
            },
          }}
        >
          {t_i18n('Filters')}
        </Button>

        {/* Personalization Button */}
        <Button
          variant="contained"
          color="secondary"
          startIcon={<SettingsIcon />}
          onClick={onPersonalizationClick}
          sx={{
            textTransform: 'none',
            minWidth: 'auto',
            whiteSpace: 'nowrap',
            '& .MuiButton-startIcon': {
              marginRight: 0.5,
            },
          }}
        >
          {t_i18n('Personalization')}
        </Button>
      </Box>

      {/* Applied Filters Section */}
      <AppliedFilters
        filters={appliedFilters}
        onRemoveFilter={(key) => {
          const newFilters = appliedFilters.filter((f) => f.key !== key);
          onAppliedFiltersChange(newFilters);
          
          // Reset corresponding dropdown
          if (key === 'risk_reduction_status') {
            setRiskReductionStatus(riskReductionStatusOptions[0]);
          } else if (key === 'confidence_level') {
            setConfidenceLevel(confidenceLevelOptions[0]);
          } else if (key === 'geographical_area') {
            setGeographicalArea(geographicalAreaOptions[0]);
          } else if (key === 'section') {
            setSection(sectionOptions[0]);
          } else if (key === 'time_range') {
            setTimeRange(timeRangeOptions[0]);
          }
        }}
        onClearAll={() => {
          setRiskReductionStatus(riskReductionStatusOptions[0]);
          setConfidenceLevel(confidenceLevelOptions[0]);
          setGeographicalArea(geographicalAreaOptions[0]);
          setSection(sectionOptions[0]);
          setTimeRange(timeRangeOptions[0]);
          onAppliedFiltersChange([]);
        }}
      />
    </Box>
  );
};

export default DashboardFilterBar;
