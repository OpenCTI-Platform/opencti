import React, { useState, useRef } from 'react';
import {
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  InputAdornment,
  IconButton,
  Tooltip,
  Chip,
  Card,
  CardContent,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Checkbox,
  TablePagination,
} from '@mui/material';
import {
  Search,
  Save,
  History,
  ErrorOutline,
  ArrowForward,
  Edit,
  Refresh,
  FilterList,
  DescriptionOutlined,
  Close,
  Visibility,
  ChevronLeft,
  ChevronRight,
} from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import SearchListPopover from './SearchListPopover';
import FilterPopover from './FilterPopover';
import FilterSidebar, { FilterGroup } from './FilterSidebar';

interface SearchExample {
  title: string;
  filters: Array<{ key: string; value: string; type?: 'operator' }>;
}

interface RecentSearch {
  id: string;
  query: string;
  timestamp: string;
}

interface SearchResult {
  id: string;
  title: string;
  attacker: string;
  source: string;
  tags: string[];
  publicationDate: string;
  registrationDate: string;
}

// Function to parse search query and extract filters
const parseSearchQuery = (query: string): FilterGroup[] => {
  const filterGroups: Record<string, { values: Set<string>; checked: Set<string> }> = {};
  
  // Regular expression to match key: "value" patterns (handles keys with underscores)
  const keyValuePattern = /(\w+(?:_\w+)*):\s*"([^"]+)"/g;
  let match;
  
  while ((match = keyValuePattern.exec(query)) !== null) {
    const key = match[1];
    const value = match[2];
    
    if (!filterGroups[key]) {
      filterGroups[key] = { values: new Set(), checked: new Set() };
    }
    filterGroups[key].values.add(value);
    filterGroups[key].checked.add(value);
  }
  
  // Mock additional values for each filter group to make it look realistic
  const mockValues: Record<string, string[]> = {
    actor: ['Qiam', 'Tapandegan', 'Gonjeshk', 'Alpha Strike Lab', 'SPIDER', 'Another Actor'],
    cve: [
      'CVE-2025-54372',
      'CVE-2025-54372',
      'CVE-2025-27865',
      'CVE-2025-54372',
      'CVE-2025-54372',
      'CVE-2025-54372',
      'CVE-2025-54372',
    ],
    country: ['Iran', 'United States', 'Russia', 'China', 'North Korea'],
    entity_type: ['vulnerability', 'malware', 'indicator', 'threat-actor'],
    last_seen: ['>=30d', '>=7d', '>=1d', 'today'],
    exploit_available: ['true', 'false'],
    exploit_in_the_wild: ['true', 'false'],
  };
  
  // Convert to FilterGroup array and add mock values
  return Object.entries(filterGroups).map(([key, data]) => {
    const checkedValues = Array.from(data.checked);
    const allValues = mockValues[key] || Array.from(data.values);
    
    // Ensure checked values are included
    const uniqueValues = Array.from(new Set([...allValues, ...checkedValues]));
    
    return {
      key,
      label: key,
      values: uniqueValues.map((value) => ({
        key,
        value,
        checked: checkedValues.includes(value),
      })),
      expanded: true,
    };
  });
};

const RessaSearch = () => {
  const { t_i18n } = useFormatter();
  const [searchValue, setSearchValue] = useState(
    'actor: "Alpha Strike Lab" cve: "CVE-2025-27865" or country: "Iran" and entity_type: "vulnerability" and last_seen: ">=30d" and exploit_available: "true" and exploit_in_the_wild: "true"'
  );
  const [hasSearched, setHasSearched] = useState(false);
  // Change this to false to see "no results" state
  const [hasResults, setHasResults] = useState(true);
  const [extractedFilters, setExtractedFilters] = useState<FilterGroup[]>([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);
  const [selectedRows, setSelectedRows] = useState<string[]>([]);
  const [historyAnchorEl, setHistoryAnchorEl] = useState<HTMLElement | null>(null);
  const [saveAnchorEl, setSaveAnchorEl] = useState<HTMLElement | null>(null);
  const [filterAnchorEl, setFilterAnchorEl] = useState<HTMLElement | null>(null);
  const [popoverWidth, setPopoverWidth] = useState<number>(400);
  const searchButtonRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLDivElement>(null);
  const saveIconRef = useRef<HTMLButtonElement>(null);
  const filterIconRef = useRef<HTMLButtonElement>(null);
  
  // Mock recent searches data
  const [recentSearches] = useState<RecentSearch[]>([
    { id: '1', query: 'asn: "12" and country: "Iran"', timestamp: '1 minute ago' },
    { id: '2', query: 'country: "Iran"', timestamp: 'a week ago' },
    { id: '3', query: 'severity: "high"', timestamp: '2 weeks ago' },
  ]);

  // Mock saved searches data
  const [savedSearches] = useState<RecentSearch[]>([
    { id: '1', query: 'asn: "12" and country: "Iran"', timestamp: '1 minute ago' },
    { id: '2', query: 'country: "Iran"', timestamp: 'a week ago' },
    { id: '3', query: 'severity: "high"', timestamp: '2 weeks ago' },
  ]);

  // Mock filters data
  const [filters] = useState([
    { id: '1', name: 'actor', label: ':actor' },
    { id: '2', name: 'country', label: ':country' },
    { id: '3', name: 'cve', label: ':cve' },
    { id: '4', name: 'last_seen', label: ':last_seen' },
    { id: '5', name: 'org', label: ':org' },
    { id: '6', name: 'asn', label: ':asn' },
    { id: '7', name: 'country_code', label: ':country_code' },
  ]);

  // Mock search results data
  const [searchResults] = useState<SearchResult[]>([
    {
      id: '1',
      title: 'Digikala user database leak report - Digikala.com',
      attacker: 'Qiyam',
      source: 'Dark Web',
      tags: ['Report', 'Leak', 'Digikala', 'Employees'],
      publicationDate: 'Yesterday',
      registrationDate: 'Yesterday',
    },
    {
      id: '2',
      title: 'ransom_2024.exe',
      attacker: 'Tapndegan',
      source: 'Russian Market',
      tags: ['Ransomware', 'cve', 'node.js'],
      publicationDate: '2 days ago',
      registrationDate: '2 days ago',
    },
    {
      id: '3',
      title: 'CVE.2025.234581',
      attacker: 'Alpha Strike Lab',
      source: 'Human Analyst',
      tags: ['Healthcare', 'Iran', 'APT'],
      publicationDate: '20 Dec 2024',
      registrationDate: '20 Dec 2024',
    },
    {
      id: '4',
      title: 'APT28',
      attacker: 'SPIDER',
      source: 'Automated Feeds',
      tags: ['Financial', 'Customer', 'Saman Bank'],
      publicationDate: '3 days ago',
      registrationDate: '3 days ago',
    },
    {
      id: '5',
      title: 'Bank account leak - 15K records',
      attacker: 'Gonjeshk',
      source: 'Dark Web',
      tags: ['Report', 'Leak', 'Financial'],
      publicationDate: '1 week ago',
      registrationDate: '1 week ago',
    },
  ]);

  const totalResults = 54; // Mock total count

  const searchExamples: SearchExample[] = [
    {
      title: t_i18n('Important banking threats'),
      filters: [
        { key: 'severity', value: '"high"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'last_seen', value: '"<= 7 days"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'country', value: '"Iran"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'entity_type', value: '"vulnerability"' },
      ],
    },
    {
      title: t_i18n('Important energy threats'),
      filters: [
        { key: 'severity', value: '"high"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'last_seen', value: '"<= 7 days"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'country', value: '"Iran"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'entity_type', value: '"vulnerability"' },
      ],
    },
    {
      title: t_i18n('New vulnerabilities'),
      filters: [
        { key: 'entity_type', value: '"vulnerability"' },
        { type: 'operator', key: 'and', value: '' },
        { key: 'status', value: '"new"' },
      ],
    },
  ];

  const handleSearch = () => {
    if (searchValue.trim()) {
      setHasSearched(true);
      // Parse the search query to extract filters
      const filters = parseSearchQuery(searchValue);
      setExtractedFilters(filters);
      // TODO: Implement actual search functionality
      // Determine if results should be shown based on query
      // Query with "Alpha Strike Lab" and "CVE-2025-27865" shows no results
      // Other queries show results
      const hasNoResultsQuery = searchValue.includes('Alpha Strike Lab') && searchValue.includes('CVE-2025-27865');
      setHasResults(!hasNoResultsQuery);
      console.log('Searching for:', searchValue);
    }
  };

  const handleSearchIconClick = (event: React.MouseEvent<HTMLElement>) => {
    if (inputRef.current) {
      setHistoryAnchorEl(inputRef.current);
      setPopoverWidth(inputRef.current.offsetWidth);
    }
  };

  const handleSaveIconClick = (event: React.MouseEvent<HTMLElement>) => {
    if (inputRef.current) {
      setSaveAnchorEl(inputRef.current);
      setPopoverWidth(inputRef.current.offsetWidth);
    }
  };

  const handleCloseHistoryPopover = () => {
    setHistoryAnchorEl(null);
  };

  const handleCloseSavePopover = () => {
    setSaveAnchorEl(null);
  };

  const handleFilterIconClick = (event: React.MouseEvent<HTMLElement>) => {
    if (inputRef.current) {
      setFilterAnchorEl(inputRef.current);
      setPopoverWidth(inputRef.current.offsetWidth);
    }
  };

  const handleCloseFilterPopover = () => {
    setFilterAnchorEl(null);
  };

  const handleSelectFilter = (filterName: string) => {
    // TODO: Implement filter selection
    console.log('Selected filter:', filterName);
    setFilterAnchorEl(null);
  };

  const handleSelectRecentSearch = (query: string) => {
    setSearchValue(query);
    setHistoryAnchorEl(null);
    setSaveAnchorEl(null);
    setHasSearched(true);
  };

  const handleEditSearch = (query: string, event: React.MouseEvent) => {
    event.stopPropagation();
    setSearchValue(query);
    setHistoryAnchorEl(null);
    setSaveAnchorEl(null);
  };

  const handleSave = () => {
    if (searchValue) {
      // TODO: Implement save functionality
      console.log('Saving search:', searchValue);
    }
  };

  const handleHistory = () => {
    // TODO: Implement history functionality
    console.log('Show search history');
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter') {
      handleSearch();
    }
  };

  const handleExampleClick = (example: SearchExample) => {
    // TODO: Apply example filters to search
    console.log('Applying example:', example);
  };

  return (
    <>
      <Breadcrumbs elements={[{ label: t_i18n('Ressa Search') }]} />
      <Box sx={{ padding: 0 }}>
        <Paper
          sx={{
            padding: 2,
            minHeight: '400px',
            boxShadow: '0px 2px 8px rgba(0, 0, 0, 0.1)',
          }}
        >
          {/* Global Search Title */}
          <Typography
            variant="h4"
            sx={{
              marginBottom: 3,
              fontWeight: 600,
            }}
          >
            {t_i18n('Global Search')}
          </Typography>

          {/* Search Bar */}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 2,
              marginBottom: 3,
            }}
          >
            {/* Search Input */}
            <Box ref={inputRef} sx={{ width: '100%', position: 'relative' }}>
            <TextField
              fullWidth
              variant="outlined"
              placeholder={t_i18n('Search domain, IP, hash, email or phrase...')}
              value={searchValue}
              onChange={(e) => setSearchValue(e.target.value)}
              onKeyDown={handleKeyDown}
              sx={{
                '& .MuiOutlinedInput-root': {
                  height: 56,
                  backgroundColor: 'background.paper',
                  '& fieldset': {
                    borderColor: 'divider',
                  },
                  '&:hover fieldset': {
                    borderColor: 'primary.main',
                  },
                  '&.Mui-focused fieldset': {
                    borderColor: 'primary.main',
                  },
                },
              }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Tooltip title={t_i18n('History')}>
                        <IconButton
                          size="small"
                          onClick={handleSearchIconClick}
                          sx={{ padding: 0.5 }}
                        >
                          <History fontSize="small" sx={{ color: 'text.secondary' }} />
                        </IconButton>
                      </Tooltip>
                      <Divider
                        orientation="vertical"
                        flexItem
                        sx={{
                          height: 20,
                          marginLeft: 0.5,
                          marginRight: 0.5,
                          borderColor: 'divider',
                          alignSelf: 'center',
                          marginTop: '2px',
                        }}
                      />
                      <Tooltip title={t_i18n('Save')}>
                        <IconButton
                          ref={saveIconRef}
                          size="small"
                          onClick={handleSaveIconClick}
                          sx={{ padding: 0.5 }}
                        >
                          <Save fontSize="small" sx={{ color: 'text.secondary' }} />
                        </IconButton>
                      </Tooltip>
                      <Divider
                        orientation="vertical"
                        flexItem
                        sx={{
                          height: 20,
                          marginLeft: 0.5,
                          marginRight: 0.5,
                          borderColor: 'divider',
                          alignSelf: 'center',
                          marginTop: '2px',
                        }}
                      />
                      <Tooltip title={t_i18n('Filters')}>
                        <IconButton
                          ref={filterIconRef}
                          size="small"
                          onClick={handleFilterIconClick}
                          sx={{ padding: 0.5 }}
                        >
                          <FilterList fontSize="small" sx={{ color: 'text.secondary' }} />
                        </IconButton>
                      </Tooltip>
                      <Divider
                        orientation="vertical"
                        flexItem
                        sx={{
                          height: 20,
                          marginLeft: 0.5,
                          marginRight: 0.5,
                          borderColor: 'divider',
                          alignSelf: 'center',
                          marginTop: '2px',
                        }}
                      />
                      <Tooltip title={t_i18n('Search')}>
                        <IconButton
                          size="small"
                          sx={{ padding: 0.5 }}
                        >
                          <Search fontSize="small" sx={{ color: 'text.secondary' }} />
                        </IconButton>
                      </Tooltip>
                      <Divider
                        orientation="vertical"
                        flexItem
                        sx={{
                          height: 20,
                          marginLeft: 0.5,
                          marginRight: 0.5,
                          borderColor: 'divider',
                          alignSelf: 'center',
                          marginTop: '2px',
                        }}
                      />
                    </Box>
                  </InputAdornment>
                ),
                endAdornment: searchValue && (
                  <InputAdornment position="end">
                    <IconButton
                      size="small"
                      onClick={() => {
                        setSearchValue('');
                        setHasSearched(false);
                        setExtractedFilters([]);
                      }}
                      sx={{ padding: 0.5 }}
                    >
                      <Close fontSize="small" sx={{ color: 'text.secondary' }} />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            </Box>

            {/* Search Button */}
            <Button
              ref={searchButtonRef}
              variant="contained"
              color="primary"
              onClick={handleSearch}
              sx={{
                minWidth: 120,
                height: 56,
                textTransform: 'none',
                fontSize: '1rem',
                fontWeight: 500,
                borderRadius: 1,
              }}
            >
              {t_i18n('Search')}
            </Button>
          </Box>

          {/* Recent Searches Popover */}
          <SearchListPopover
            open={Boolean(historyAnchorEl)}
            anchorEl={historyAnchorEl}
            onClose={handleCloseHistoryPopover}
            width={popoverWidth}
            title={t_i18n('Recent searches')}
            items={recentSearches}
            icon={<History fontSize="small" sx={{ color: 'text.secondary' }} />}
            onSelectItem={handleSelectRecentSearch}
            onEditItem={handleEditSearch}
            onSave={handleSave}
            saveButtonText={t_i18n('Save Search')}
          />

          {/* Saved Searches Popover */}
          <SearchListPopover
            open={Boolean(saveAnchorEl)}
            anchorEl={saveAnchorEl}
            onClose={handleCloseSavePopover}
            width={popoverWidth}
            title={t_i18n('Saved searches')}
            items={savedSearches}
            icon={<Save fontSize="small" sx={{ color: 'text.secondary' }} />}
            onSelectItem={handleSelectRecentSearch}
            onEditItem={handleEditSearch}
            onSave={handleSave}
            saveButtonText={t_i18n('Save Search')}
          />

          {/* Filters Popover */}
          <FilterPopover
            open={Boolean(filterAnchorEl)}
            anchorEl={filterAnchorEl}
            onClose={handleCloseFilterPopover}
            width={popoverWidth}
            title={t_i18n('Filters')}
            filters={filters}
            onSelectFilter={handleSelectFilter}
          />

          {/* No Search State */}
          {!hasSearched && (
            <Box
              sx={{
                marginTop: 6,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {/* Icon */}
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: '50%',
                  backgroundColor: 'action.hover',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: 3,
                }}
              >
                <ErrorOutline
                  sx={{
                    fontSize: 48,
                    color: 'text.secondary',
                  }}
                />
              </Box>

              {/* Title */}
              <Typography
                variant="h5"
                sx={{
                  fontWeight: 600,
                  marginBottom: 1,
                  textAlign: 'center',
                }}
              >
                {t_i18n('No search has been performed yet')}
              </Typography>

              {/* Subtitle */}
              <Typography
                variant="body1"
                color="text.secondary"
                sx={{
                  marginBottom: 4,
                  textAlign: 'center',
                }}
              >
                {t_i18n('You can start with the examples below')}
              </Typography>

              {/* Example Cards */}
              <Box
                sx={{
                  width: '100%',
                  maxWidth: 800,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 2,
                }}
              >
                {searchExamples.map((example, index) => (
                  <Card
                    key={index}
                    sx={{
                      cursor: 'pointer',
                      transition: 'all 0.2s',
                      border: '1px solid rgba(0, 0, 0, 0.06)',
                      '&:hover': {
                        boxShadow: 3,
                        transform: 'translateY(-2px)',
                      },
                    }}
                    onClick={() => handleExampleClick(example)}
                  >
                    <CardContent>
                      <Box
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 2,
                        }}
                      >
                        <Box sx={{ flex: 1 }}>
                          <Typography
                            variant="subtitle1"
                            sx={{
                              fontWeight: 500,
                              marginBottom: 1.5,
                            }}
                          >
                            {example.title}
                          </Typography>
                          <Box
                            sx={{
                              display: 'flex',
                              flexWrap: 'wrap',
                              gap: 1,
                              alignItems: 'center',
                            }}
                          >
                            {example.filters.map((filter, filterIndex) => {
                              if (filter.type === 'operator') {
                                return (
                                  <Chip
                                    key={filterIndex}
                                    label={filter.key}
                                    size="small"
                                    sx={{
                                      backgroundColor: '#F3F8FF', // Light blue background for "and" operators
                                      color: '#5C7BF5', // Blue text color
                                      border: 'none',
                                      fontWeight: 500,
                                      borderRadius: '4px',
                                    }}
                                  />
                                );
                              }
                              return (
                                <Chip
                                  key={filterIndex}
                                  label={
                                    <Box component="span">
                                      {filter.key}: <Box component="span" sx={{ fontWeight: 700 }}>{filter.value}</Box>
                                    </Box>
                                  }
                                  size="small"
                                  sx={{
                                    backgroundColor: '#E8E4F7', // Light purple background
                                    color: '#6B46C1', // Dark purple text
                                    border: 'none',
                                    borderRadius: '4px',
                                    '& .MuiChip-label': {
                                      fontWeight: 500,
                                    },
                                  }}
                                />
                              );
                            })}
                          </Box>
                        </Box>
                        <ArrowForward
                          sx={{
                            color: 'text.secondary',
                            fontSize: 20,
                          }}
                        />
                      </Box>
                    </CardContent>
                  </Card>
                ))}
              </Box>
            </Box>
          )}

          {/* Search Results or No Results State */}
          {hasSearched && (
            <Box
              sx={{
                marginTop: 4,
                display: 'flex',
                gap: 3,
                maxHeight: 'calc(100vh - 300px)',
                minHeight: 400,
              }}
            >
              {/* Filter Sidebar - Left Side for LTR */}
              {extractedFilters.length > 0 && (
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <FilterSidebar
                    filters={extractedFilters}
                    onFilterChange={(filterKey, value, checked) => {
                      // Update filter state
                      setExtractedFilters((prev) =>
                        prev.map((filter) => {
                          if (filter.key === filterKey) {
                            return {
                              ...filter,
                              values: filter.values.map((v) =>
                                v.value === value ? { ...v, checked } : v
                              ),
                            };
                          }
                          return filter;
                        })
                      );
                      // TODO: Trigger new search with updated filters
                    }}
                  />
                </Box>
              )}

              {/* Main Content Area */}
              <Box sx={{ flex: 5, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <Card
                  sx={{
                    flex: 1,
                    display: 'flex',
                    flexDirection: 'column',
                    boxShadow: '0px 2px 8px rgba(0, 0, 0, 0.1)',
                    borderRadius: 1,
                    border: '1px solid',
                    borderColor: 'divider',
                    minHeight: 0,
                    overflow: 'hidden',
                  }}
                >
                  <CardContent
                    sx={{
                      flex: 1,
                      display: 'flex',
                      flexDirection: 'column',
                      padding: 0,
                      minHeight: 0,
                      overflow: 'hidden',
                    }}
                  >
                    {/* Results Count and Save Search Button */}
                    <Box
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: 2,
                      }}
                    >
                      {/* Results Count */}
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 1,
                        }}
                      >
                        {t_i18n('Results found')}
                        <Box
                          sx={{
                            width: 8,
                            height: 8,
                            borderRadius: '50%',
                            backgroundColor: 'primary.main',
                          }}
                        />
                        <Typography component="span" variant="body2" sx={{ fontWeight: 500 }}>
                          {hasSearched ? totalResults : 0}
                        </Typography>
                      </Typography>

                      {/* Save Search Button */}
                      <Button
                        variant="outlined"
                        startIcon={<Save />}
                        onClick={handleSave}
                        sx={{
                          textTransform: 'none',
                          paddingX: 2,
                          paddingY: 1.5,
                        }}
                      >
                        {t_i18n('Save Search')}
                      </Button>
                    </Box>

                    {/* Divider */}
                    <Divider />

                    {/* Results Content */}
                    <Box
                      sx={{
                        flex: 1,
                        display: 'flex',
                        flexDirection: 'column',
                        padding: 2,
                        minHeight: 0,
                        overflow: 'auto',
                      }}
                    >
                    {hasResults ? (
                      <Box
                        sx={{
                          flex: 1,
                          display: 'flex',
                          flexDirection: 'column',
                          minHeight: 0,
                        }}
                      >
                        {/* Pagination Info */}
                        <Box
                          sx={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: 2,
                            borderBottom: '1px solid',
                            borderColor: 'divider',
                          }}
                        >
                          <Typography variant="body2" color="text.secondary">
                            {t_i18n('Display')} {page * rowsPerPage + 1}-{Math.min((page + 1) * rowsPerPage, totalResults)} {t_i18n('of')} {totalResults}
                          </Typography>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <IconButton
                              size="small"
                              onClick={() => setPage((prev) => Math.max(0, prev - 1))}
                              disabled={page === 0}
                            >
                              <ChevronLeft />
                            </IconButton>
                            {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map((num) => (
                              <Button
                                key={num}
                                size="small"
                                variant={page + 1 === num ? 'contained' : 'outlined'}
                                onClick={() => setPage(num - 1)}
                                sx={{ minWidth: 32, height: 32 }}
                              >
                                {num}
                              </Button>
                            ))}
                            <IconButton
                              size="small"
                              onClick={() => setPage((prev) => prev + 1)}
                              disabled={(page + 1) * rowsPerPage >= totalResults}
                            >
                              <ChevronRight />
                            </IconButton>
                          </Box>
                        </Box>

                        {/* Table */}
                        <TableContainer sx={{ flex: 1, overflow: 'auto' }}>
                          <Table stickyHeader>
                            <TableHead>
                              <TableRow>
                                <TableCell padding="checkbox" sx={{ width: 48 }}>
                                  <Checkbox
                                    indeterminate={
                                      selectedRows.length > 0 && selectedRows.length < searchResults.length
                                    }
                                    checked={selectedRows.length === searchResults.length && searchResults.length > 0}
                                    onChange={(e) => {
                                      if (e.target.checked) {
                                        setSelectedRows(searchResults.map((r) => r.id));
                                      } else {
                                        setSelectedRows([]);
                                      }
                                    }}
                                  />
                                </TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Title')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Attacker')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Source')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Tags')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Publication Date')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Registration Date')}</TableCell>
                                <TableCell sx={{ fontWeight: 600, width: 100 }}>{t_i18n('View')}</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {searchResults
                                .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage)
                                .map((result) => (
                                  <TableRow key={result.id} hover>
                                    <TableCell padding="checkbox">
                                      <Checkbox
                                        checked={selectedRows.includes(result.id)}
                                        onChange={(e) => {
                                          if (e.target.checked) {
                                            setSelectedRows([...selectedRows, result.id]);
                                          } else {
                                            setSelectedRows(selectedRows.filter((id) => id !== result.id));
                                          }
                                        }}
                                      />
                                    </TableCell>
                                    <TableCell>{result.title}</TableCell>
                                    <TableCell>{result.attacker}</TableCell>
                                    <TableCell>{result.source}</TableCell>
                                    <TableCell>
                                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                        {result.tags.map((tag, index) => (
                                          <Chip
                                            key={index}
                                            label={tag}
                                            size="small"
                                            sx={{
                                              height: 24,
                                              fontSize: '0.75rem',
                                              borderRadius: 1,
                                              backgroundColor: (theme) => {
                                                const colors = [
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(76, 175, 80, 0.15)'
                                                    : 'rgba(76, 175, 80, 0.1)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(255, 152, 0, 0.15)'
                                                    : 'rgba(255, 152, 0, 0.1)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(33, 150, 243, 0.15)'
                                                    : 'rgba(33, 150, 243, 0.1)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(244, 67, 54, 0.15)'
                                                    : 'rgba(244, 67, 54, 0.1)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(156, 39, 176, 0.15)'
                                                    : 'rgba(156, 39, 176, 0.1)',
                                                ];
                                                return colors[index % colors.length];
                                              },
                                              border: (theme) => {
                                                const borderColors = [
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(76, 175, 80, 0.6)'
                                                    : 'rgba(76, 175, 80, 0.5)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(255, 152, 0, 0.6)'
                                                    : 'rgba(255, 152, 0, 0.5)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(33, 150, 243, 0.6)'
                                                    : 'rgba(33, 150, 243, 0.5)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(244, 67, 54, 0.6)'
                                                    : 'rgba(244, 67, 54, 0.5)',
                                                  theme.palette.mode === 'dark'
                                                    ? 'rgba(156, 39, 176, 0.6)'
                                                    : 'rgba(156, 39, 176, 0.5)',
                                                ];
                                                return `1px solid ${borderColors[index % borderColors.length]}`;
                                              },
                                            }}
                                          />
                                        ))}
                                      </Box>
                                    </TableCell>
                                    <TableCell>{result.publicationDate}</TableCell>
                                    <TableCell>{result.registrationDate}</TableCell>
                                    <TableCell>
                                      <Button
                                        size="small"
                                        variant="outlined"
                                        startIcon={<Visibility fontSize="small" />}
                                        sx={{ textTransform: 'none' }}
                                      >
                                        {t_i18n('View')}
                                      </Button>
                                    </TableCell>
                                  </TableRow>
                                ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </Box>
                    ) : (
                      <Box
                        sx={{
                          flex: 1,
                          display: 'flex',
                          flexDirection: 'column',
                          alignItems: 'center',
                          justifyContent: 'center',
                          minHeight: 300,
                        }}
                      >
                        {/* Icon */}
                        <Box
                          sx={{
                            width: 120,
                            height: 120,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            marginBottom: 3,
                            color: 'text.secondary',
                            opacity: 0.5,
                          }}
                        >
                          <DescriptionOutlined sx={{ fontSize: 120 }} />
                        </Box>

                        {/* Title */}
                        <Typography
                          variant="h5"
                          sx={{
                            fontWeight: 600,
                            marginBottom: 1.5,
                            textAlign: 'center',
                          }}
                        >
                          {t_i18n('No results were found')}
                        </Typography>

                        {/* Description */}
                        <Typography
                          variant="body1"
                          color="text.secondary"
                          sx={{
                            textAlign: 'center',
                            maxWidth: 500,
                          }}
                        >
                          {t_i18n('No items matching your search were found. Review the filters.')}
                        </Typography>
                      </Box>
                    )}
                    </Box>
                  </CardContent>
                </Card>
              </Box>
            </Box>
          )}
        </Paper>
      </Box>
    </>
  );
};

export default RessaSearch;
