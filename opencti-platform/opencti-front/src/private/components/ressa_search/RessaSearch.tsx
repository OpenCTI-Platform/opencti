import React, { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  Box,
  Typography,
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
  Select,
  MenuItem,
  FormControl,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextareaAutosize,
  Alert,
  CircularProgress,
} from '@mui/material';
import {
  Search,
  Save,
  History,
  ErrorOutline,
  ArrowForward,
  FilterList,
  DescriptionOutlined,
  Close,
  Visibility,
  ChevronLeft,
  ChevronRight,
  Download,
  Settings,
} from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import SearchListPopover from './SearchListPopover';
import FilterPopover from './FilterPopover';
import FilterSidebar, { FilterGroup } from './FilterSidebar';
import { RawQueryResponse } from './mockRessaSearchApi';
import { rawQueryApi } from './ressaSearchApi';
import { clearRessaSearchSession, loadRessaSearchSession, RESSA_SEARCH_QUERY_PARAM, saveRessaSearchSession } from './ressaSearchSession';

interface SearchExample {
  title: string;
  query: string;
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
  tags: string[];
  publicationDate: string;
  registrationDate: string;
  entityType: string;
  standardId: string;
}

// Function to parse search query and extract filters
const parseSearchQuery = (query: string): FilterGroup[] => {
  const filterGroups: Record<string, { values: Set<string>; checked: Set<string> }> = {};

  // Regular expression to match key: "value" patterns (handles keys with underscores)
  const keyValuePattern = /(\w+(?:_\w+)*):\s*"([^"]+)"/g;
  // SPL-like pattern used by the raw query API: key="value"
  const splEqualsPattern = /(\w+(?:_\w+)*)="([^"]+)"/g;
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

  while ((match = splEqualsPattern.exec(query)) !== null) {
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
  const [searchParams, setSearchParams] = useSearchParams();
  const hasRestoredFromUrlRef = useRef(false);
  const initialQueryRef = useRef(searchParams.get(RESSA_SEARCH_QUERY_PARAM));
  const [searchValue, setSearchValue] = useState('');
  const [hasSearched, setHasSearched] = useState(false);
  const [extractedFilters, setExtractedFilters] = useState<FilterGroup[]>([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);
  const [selectedRows, setSelectedRows] = useState<string[]>([]);
  const [historyAnchorEl, setHistoryAnchorEl] = useState<HTMLElement | null>(null);
  const [saveAnchorEl, setSaveAnchorEl] = useState<HTMLElement | null>(null);
  const [filterAnchorEl, setFilterAnchorEl] = useState<HTMLElement | null>(null);
  const [popoverWidth, setPopoverWidth] = useState<number>(400);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [saveTitle, setSaveTitle] = useState('');
  const [saveDescription, setSaveDescription] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [rawResponse, setRawResponse] = useState<RawQueryResponse | null>(null);
  const hasResults = (rawResponse?.stats?.primaryDocumentCount ?? 0) > 0;
  const searchButtonRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLDivElement>(null);
  const saveIconRef = useRef<HTMLButtonElement>(null);
  const filterIconRef = useRef<HTMLButtonElement>(null);

  const observedDataUrlCredentialsQuery
    = 'type="observed-data" | spath path=objects{} output=obj | mvexpand obj | spath input=obj path=type output=obj_type | search obj_type="url" | spath input=obj path=extensions{}.login output=login | spath input=obj path=extensions{}.password output=password | spath input=obj path=extensions{}.cookie output=cookie | search login=true AND password=true AND cookie=true | table obj.value login password cookie';

  // Mock recent searches data
  const [recentSearches] = useState<RecentSearch[]>([
    { id: '1', query: observedDataUrlCredentialsQuery, timestamp: '1 minute ago' },
    { id: '2', query: 'type="report" | table name entity_type created_at updated_at', timestamp: 'a week ago' },
    { id: '3', query: 'type="vulnerability" | table name standard_id created_at updated_at', timestamp: '2 weeks ago' },
  ]);

  // Mock saved searches data
  const [savedSearches] = useState<RecentSearch[]>([
    { id: '1', query: observedDataUrlCredentialsQuery, timestamp: '1 minute ago' },
    { id: '2', query: 'type="observed-data" | table internal_id standard_id entity_type', timestamp: 'a week ago' },
    { id: '3', query: 'type="indicator" | table name standard_id created_at updated_at', timestamp: '2 weeks ago' },
  ]);

  // Mock filters data
  const [filters] = useState([
    { id: '1', name: 'type', label: ':type' },
    { id: '2', name: 'entity_type', label: ':entity_type' },
    { id: '3', name: 'objects{}', label: ':objects{}' },
    { id: '4', name: 'extensions{}', label: ':extensions{}' },
  ]);

  const searchResults: SearchResult[] = useMemo(() => {
    if (!rawResponse) return [];
    return rawResponse.primaryDocuments.map((doc) => {
      const src = (doc.source ?? {}) as Record<string, unknown>;
      const name = typeof src.name === 'string' ? src.name : undefined;
      const title = name ?? doc.standardId ?? doc.internalId;
      const createdAt = typeof src.created_at === 'string' ? src.created_at : undefined;
      const updatedAt = typeof src.updated_at === 'string' ? src.updated_at : undefined;
      const labels = Array.isArray(src.labels)
        ? (src.labels.filter((x) => typeof x === 'string') as string[])
        : [];
      const entityType = typeof src.entity_type === 'string' ? src.entity_type : doc.entityType;

      return {
        id: doc.internalId,
        title,
        tags: Array.from(new Set([entityType, ...labels])).slice(0, 8),
        publicationDate: updatedAt ?? '',
        registrationDate: createdAt ?? '',
        entityType: doc.entityType,
        standardId: doc.standardId,
      };
    });
  }, [rawResponse]);

  const totalResults = rawResponse?.stats?.primaryDocumentCount ?? searchResults.length;
  const pageCount = Math.max(1, Math.ceil(totalResults / rowsPerPage));
  const safePage = Math.min(page, pageCount - 1);

  const searchExamples: SearchExample[] = [
    {
      title: t_i18n('Important banking threats'),
      query: observedDataUrlCredentialsQuery,
      filters: [
        { key: 'type', value: '"observed-data"' },
        { type: 'operator', key: '|', value: '' },
        { key: 'search', value: 'obj_type="url"' },
        { type: 'operator', key: '|', value: '' },
        { key: 'table', value: 'obj.value login password cookie' },
      ],
    },
    {
      title: t_i18n('Important energy threats'),
      query: 'type="observed-data" | table internal_id standard_id entity_type created_at updated_at',
      filters: [
        { key: 'type', value: '"observed-data"' },
        { type: 'operator', key: '|', value: '' },
        { key: 'table', value: 'internal_id standard_id entity_type created_at updated_at' },
      ],
    },
    {
      title: t_i18n('New vulnerabilities'),
      query: 'type="vulnerability" | table name standard_id created_at updated_at',
      filters: [
        { key: 'type', value: '"vulnerability"' },
        { type: 'operator', key: '|', value: '' },
        { key: 'table', value: 'name standard_id created_at updated_at' },
      ],
    },
  ];

  const runSearch = useCallback(async (query: string) => {
    const trimmed = query.trim();
    if (!trimmed || isSearching) return;

    hasRestoredFromUrlRef.current = true;
    setHasSearched(true);
    setSearchError(null);
    setIsSearching(true);
    setSelectedRows([]);
    setPage(0);

    const filters = parseSearchQuery(trimmed);
    setExtractedFilters(filters);
    setSearchValue(trimmed);
    setSearchParams({ [RESSA_SEARCH_QUERY_PARAM]: trimmed }, { replace: true });

    try {
      const request = {
        query: trimmed,
        maxRelationDepth: 20,
        maxPrimaryDocuments: 20,
        maxRelatedEntities: 20,
        maxRelationships: 20,
        maxRelatedDocuments: 20,
        includeRelationshipDocuments: true,
        includeNestedObjects: true,
        includeMetadataAndHistory: true,
        multilineOutput: true,
      } as const;

      const response = await rawQueryApi(request);
      setRawResponse(response);
      saveRessaSearchSession({
        searchValue: trimmed,
        rawResponse: response,
        extractedFilters: filters,
        page: 0,
        rowsPerPage,
      });
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Unknown error';
      setRawResponse(null);
      setSearchError(message);
      clearRessaSearchSession();
    } finally {
      setIsSearching(false);
    }
  }, [isSearching, rowsPerPage, setSearchParams]);

  const handleSearch = () => {
    runSearch(searchValue);
  };

  const clearSearchState = useCallback(() => {
    hasRestoredFromUrlRef.current = false;
    clearRessaSearchSession();
    setSearchParams({}, { replace: true });
    setSearchValue('');
    setHasSearched(false);
    setExtractedFilters([]);
    setRawResponse(null);
    setSearchError(null);
    setPage(0);
    setSelectedRows([]);
  }, [setSearchParams]);

  useEffect(() => {
    const q = initialQueryRef.current;
    if (!q || hasRestoredFromUrlRef.current) return;
    hasRestoredFromUrlRef.current = true;

    const saved = loadRessaSearchSession();
    if (saved?.searchValue === q && saved.rawResponse) {
      setSearchValue(saved.searchValue);
      setRawResponse(saved.rawResponse);
      setExtractedFilters(saved.extractedFilters);
      setPage(saved.page ?? 0);
      setRowsPerPage(saved.rowsPerPage ?? 20);
      setHasSearched(true);
      setSearchError(null);
      return;
    }

    runSearch(q);
  }, [runSearch]);

  useEffect(() => {
    if (!hasSearched || !rawResponse || !searchValue.trim()) return;
    saveRessaSearchSession({
      searchValue,
      rawResponse,
      extractedFilters,
      page,
      rowsPerPage,
    });
  }, [page, rowsPerPage, hasSearched, rawResponse, searchValue, extractedFilters]);

  const handleSearchIconClick = () => {
    if (inputRef.current) {
      setHistoryAnchorEl(inputRef.current);
      setPopoverWidth(inputRef.current.offsetWidth);
    }
  };

  const handleSaveIconClick = () => {
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

  const handleFilterIconClick = () => {
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
    setExtractedFilters(parseSearchQuery(query));
    setHistoryAnchorEl(null);
    setSaveAnchorEl(null);
    setHasSearched(true);
  };

  const handleEditSearch = (query: string, event: React.MouseEvent) => {
    event.stopPropagation();
    setSearchValue(query);
    setExtractedFilters(parseSearchQuery(query));
    setHistoryAnchorEl(null);
    setSaveAnchorEl(null);
  };

  // Parse query to chips for display
  const parseQueryToChips = (query: string) => {
    const chips: Array<{ type: 'filter' | 'operator'; key?: string; value?: string; label: string }> = [];
    const parts = query.split(/\s+(and|or)\s+/i);

    parts.forEach((part, _index) => {
      if (part.toLowerCase() === 'and' || part.toLowerCase() === 'or') {
        chips.push({
          type: 'operator',
          label: part.toLowerCase(),
        });
      } else {
        const match = part.match(/(\w+(?:_\w+)*):\s*"([^"]+)"/);
        if (match) {
          chips.push({
            type: 'filter',
            key: match[1],
            value: match[2],
            label: `${match[1]}: "${match[2]}"`,
          });
        }
      }
    });

    return chips;
  };

  const handleSave = () => {
    setSaveDialogOpen(true);
    setSaveTitle('');
    setSaveDescription('');
  };

  const handleSaveSearch = () => {
    if (saveTitle.trim() && searchValue) {
      // TODO: Implement save functionality
      console.log('Saving search:', { title: saveTitle, query: searchValue, description: saveDescription });
      setSaveDialogOpen(false);
      setSaveTitle('');
      setSaveDescription('');
    }
  };

  const handleCloseSaveDialog = () => {
    setSaveDialogOpen(false);
    setSaveTitle('');
    setSaveDescription('');
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter') {
      handleSearch();
    }
  };

  const handleExampleClick = (example: SearchExample) => {
    runSearch(example.query);
  };

  return (
    <>
      {/* <Breadcrumbs elements={[{ label: t_i18n('Ressa Search') }]} /> */}
      <Box sx={{ padding: 0 }}>

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
              disabled={isSearching}
              sx={{
                '& .MuiOutlinedInput-root': {
                  height: 40,
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
                          marginInlineStart: 0.5,
                          marginInlineEnd: 0.5,
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
                          marginInlineStart: 0.5,
                          marginInlineEnd: 0.5,
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
                          marginInlineStart: 0.5,
                          marginInlineEnd: 0.5,
                          borderColor: 'divider',
                          alignSelf: 'center',
                          marginTop: '2px',
                        }}
                      />
                      <Tooltip title={t_i18n('Search')}>
                        <IconButton
                          size="small"
                          onClick={handleSearch}
                          sx={{ padding: 0.5 }}
                        >
                          {isSearching ? (
                            <CircularProgress size={16} />
                          ) : (
                            <Search fontSize="small" sx={{ color: 'text.secondary' }} />
                          )}
                        </IconButton>
                      </Tooltip>
                      <Divider
                        orientation="vertical"
                        flexItem
                        sx={{
                          height: 20,
                          marginInlineStart: 0.5,
                          marginInlineEnd: 0.5,
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
                      onClick={clearSearchState}
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
            disabled={isSearching || !searchValue.trim()}
            sx={{
              minWidth: 100,
              height: 40,
              textTransform: 'none',
              fontSize: '1rem',
              fontWeight: 500,
              borderRadius: 1,
            }}
          >
            {isSearching ? t_i18n('Searching...') : t_i18n('Search')}
          </Button>
        </Box>

        {hasSearched && searchError && (
          <Box sx={{ mb: 2 }}>
            <Alert severity="error">{searchError}</Alert>
          </Box>
        )}

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
                                label={(
                                  <Box component="span">
                                    {filter.key}:{' '}
                                    <Box component="span" sx={{ fontWeight: 700 }}>
                                      {filter.value}
                                    </Box>
                                  </Box>
                                )}
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
              gap: 0,
              maxHeight: 'calc(100vh - 300px)',
              minHeight: 400,
              borderRadius: 1,
              border: '1px solid',
              borderColor: 'divider',
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
                              v.value === value ? { ...v, checked } : v,
                            ),
                          };
                        }
                        return filter;
                      }),
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
                  minHeight: 0,
                  overflow: 'hidden',
                  boxShadow: 'none',
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
                      variant="h6"
                      color="text.secondary"
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 1,
                      }}
                    >
                      {t_i18n('Results found') + ':'}
                      <Box
                        sx={{
                          width: 24,
                          height: 24,
                          borderRadius: '50%',
                          backgroundColor: 'action.hover',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}
                      >
                        <Typography component="span" variant="body2" sx={{ fontWeight: 500 }}>
                          {totalResults}
                        </Typography>
                      </Box>
                    </Typography>

                    {/* Save Search Button */}
                    <Button
                      variant="outlined"
                      startIcon={<Save />}
                      onClick={handleSave}
                      sx={{
                        textTransform: 'none',
                        paddingX: 2,
                        paddingY: 1,
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
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography variant="body2" color="text.secondary">
                              {t_i18n('Display')} {page * rowsPerPage + 1}-{Math.min((page + 1) * rowsPerPage, totalResults)} {t_i18n('of')} {totalResults}
                            </Typography>
                            <Divider
                              orientation="vertical"
                              flexItem
                              sx={{
                                height: 24,
                                marginX: 0.5,
                                borderColor: 'divider',
                                alignSelf: 'center',
                              }}
                            />
                            <FormControl size="small" sx={{ minWidth: 80 }}>
                              <Select
                                value={rowsPerPage}
                                onChange={(e) => {
                                  setRowsPerPage(Number(e.target.value));
                                  setPage(0);
                                }}
                                variant="outlined"
                                sx={{
                                  height: 32,
                                  fontSize: '0.875rem',
                                }}
                              >
                                <MenuItem value={5}>5</MenuItem>
                                <MenuItem value={10}>10</MenuItem>
                                <MenuItem value={20}>20</MenuItem>
                                <MenuItem value={50}>50</MenuItem>
                                <MenuItem value={100}>100</MenuItem>
                              </Select>
                            </FormControl>
                          </Box>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <IconButton
                              size="small"
                              onClick={() => setPage((prev) => Math.max(0, prev - 1))}
                              disabled={safePage === 0}
                            >
                              <ChevronLeft />
                            </IconButton>
                            {(() => {
                              const current = safePage + 1;
                              const total = pageCount;
                              const windowSize = 7;
                              const half = Math.floor(windowSize / 2);
                              let start = Math.max(1, current - half);
                              const end = Math.min(total, start + windowSize - 1);
                              start = Math.max(1, end - windowSize + 1);

                              const pages: Array<number | 'ellipsis'> = [];
                              if (start > 1) pages.push(1);
                              if (start > 2) pages.push('ellipsis');
                              for (let p = start; p <= end; p += 1) pages.push(p);
                              if (end < total - 1) pages.push('ellipsis');
                              if (end < total) pages.push(total);

                              return pages.map((p, idx) => {
                                if (p === 'ellipsis') {
                                  return (
                                    <Box
                                      key={`ellipsis-${idx}`}
                                      sx={{ px: 0.5, color: 'text.secondary' }}
                                    >
                                      …
                                    </Box>
                                  );
                                }
                                return (
                                  <Button
                                    key={p}
                                    size="small"
                                    variant={safePage + 1 === p ? 'contained' : 'outlined'}
                                    onClick={() => setPage(p - 1)}
                                    sx={{ minWidth: 32, height: 32 }}
                                  >
                                    {p}
                                  </Button>
                                );
                              });
                            })()}
                            <IconButton
                              size="small"
                              onClick={() => setPage((prev) => Math.min(pageCount - 1, prev + 1))}
                              disabled={safePage >= pageCount - 1}
                            >
                              <ChevronRight />
                            </IconButton>
                            <Divider
                              orientation="vertical"
                              flexItem
                              sx={{
                                height: 24,
                                marginX: 0.5,
                                borderColor: 'divider',
                                alignSelf: 'center',
                              }}
                            />
                            <IconButton
                              size="small"
                              onClick={() => {
                                // TODO: Implement download functionality
                                console.log('Download clicked');
                              }}
                              sx={{
                                border: '1px solid',
                                borderColor: 'divider',
                                borderRadius: 1,
                              }}
                            >
                              <Download fontSize="small" />
                            </IconButton>
                            <IconButton
                              size="small"
                              onClick={() => {
                                // TODO: Implement settings functionality
                                console.log('Settings clicked');
                              }}
                              sx={{
                                border: '1px solid',
                                borderColor: 'divider',
                                borderRadius: 1,
                              }}
                            >
                              <Settings fontSize="small" />
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
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Entity Type')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Tags')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Updated')}</TableCell>
                                <TableCell sx={{ fontWeight: 600 }}>{t_i18n('Created')}</TableCell>
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
                                    <TableCell>
                                      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                        <Typography variant="body2">{result.title}</Typography>
                                        <Typography variant="caption" color="text.secondary">
                                          {result.standardId}
                                        </Typography>
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
                                      </Box>
                                    </TableCell>
                                    <TableCell>{result.entityType}</TableCell>
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
                                        component={Link}
                                        to={`/dashboard/id/${result.id}`}
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
      </Box>

      {/* Save Search Dialog */}
      <Dialog
        open={saveDialogOpen}
        onClose={handleCloseSaveDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Typography variant="h6">{t_i18n('Save Search')}</Typography>
            <IconButton
              size="small"
              onClick={handleCloseSaveDialog}
              sx={{ padding: 0.5 }}
            >
              <Close />
            </IconButton>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, paddingTop: 2 }}>
            {/* Title Field */}
            <TextField
              fullWidth
              label={t_i18n('Title')}
              required
              value={saveTitle}
              onChange={(e) => setSaveTitle(e.target.value)}
              placeholder={t_i18n('Enter search title')}
            />

            {/* Query Field */}
            <Box>
              <Typography variant="body2" sx={{ marginBottom: 1, fontWeight: 500 }}>
                {t_i18n('Query')} <Typography component="span" sx={{ color: 'error.main' }}>*</Typography>
              </Typography>
              <Box
                sx={{
                  padding: 2,
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 1,
                  backgroundColor: 'background.default',
                  minHeight: 60,
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 1,
                  alignItems: 'center',
                }}
              >
                {parseQueryToChips(searchValue).map((chip, index) => {
                  if (chip.type === 'operator') {
                    return (
                      <Chip
                        key={index}
                        label={chip.label}
                        size="small"
                        sx={{
                          backgroundColor: '#F3F8FF',
                          color: '#5C7BF5',
                          border: 'none',
                          fontWeight: 500,
                          borderRadius: 1,
                        }}
                      />
                    );
                  }
                  return (
                    <Chip
                      key={index}
                      label={chip.label}
                      size="small"
                      sx={{
                        backgroundColor: '#E8E4F7',
                        color: '#6B46C1',
                        border: 'none',
                        borderRadius: 1,
                        '& .MuiChip-label': {
                          fontWeight: 500,
                        },
                      }}
                    />
                  );
                })}
              </Box>
            </Box>

            {/* Description Field */}
            <Box>
              <Typography variant="body2" sx={{ marginBottom: 1, fontWeight: 500 }}>
                {t_i18n('Description')}
              </Typography>
              <TextareaAutosize
                minRows={4}
                value={saveDescription}
                onChange={(e) => setSaveDescription(e.target.value)}
                placeholder={t_i18n('Enter description (optional)')}
                style={{
                  width: '100%',
                  padding: '12px',
                  border: '1px solid',
                  borderColor: '#d0d0d0',
                  borderRadius: '4px',
                  fontSize: '0.875rem',
                  fontFamily: 'inherit',
                  resize: 'vertical',
                }}
              />
            </Box>
          </Box>
        </DialogContent>
        <DialogActions sx={{ padding: 2 }}>
          <Button onClick={handleCloseSaveDialog} variant="outlined">
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleSaveSearch}
            variant="contained"
            disabled={!saveTitle.trim()}
            sx={{
              backgroundColor: '#6B46C1',
              '&:hover': {
                backgroundColor: '#5B36A1',
              },
            }}
          >
            {t_i18n('Save')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default RessaSearch;
