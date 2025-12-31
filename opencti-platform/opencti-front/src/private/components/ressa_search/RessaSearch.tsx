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
  Popover,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
} from '@mui/material';
import {
  Search,
  Save,
  History,
  ErrorOutline,
  ArrowForward,
  Edit,
  Refresh,
} from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

interface SearchExample {
  title: string;
  filters: Array<{ key: string; value: string; type?: 'operator' }>;
}

interface RecentSearch {
  id: string;
  query: string;
  timestamp: string;
}

const RessaSearch = () => {
  const { t_i18n } = useFormatter();
  const [searchValue, setSearchValue] = useState('');
  const [hasSearched, setHasSearched] = useState(false);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [hoveredItemId, setHoveredItemId] = useState<string | null>(null);
  const searchButtonRef = useRef<HTMLButtonElement>(null);
  const inputRef = useRef<HTMLDivElement>(null);
  
  // Mock recent searches data
  const [recentSearches] = useState<RecentSearch[]>([
    { id: '1', query: 'asn: "12" and country: "Iran"', timestamp: '1 minute ago' },
    { id: '2', query: 'country: "Iran"', timestamp: 'a week ago' },
    { id: '3', query: 'severity: "high"', timestamp: '2 weeks ago' },
  ]);

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

  const handleSearch = (event?: React.MouseEvent<HTMLButtonElement>) => {
    if (event && searchButtonRef.current) {
      setAnchorEl(searchButtonRef.current);
    }
    if (searchValue.trim()) {
      setHasSearched(true);
      // TODO: Implement search functionality
      console.log('Searching for:', searchValue);
    }
  };

  const handleSearchIconClick = (event: React.MouseEvent<HTMLElement>) => {
    if (inputRef.current) {
      setAnchorEl(inputRef.current);
    }
  };

  const handleClosePopover = () => {
    setAnchorEl(null);
  };

  const handleSelectRecentSearch = (query: string) => {
    setSearchValue(query);
    setAnchorEl(null);
    setHasSearched(true);
  };

  const handleEditSearch = (query: string, event: React.MouseEvent) => {
    event.stopPropagation();
    setSearchValue(query);
    setAnchorEl(null);
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
                          onClick={handleHistory}
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
                          size="small"
                          onClick={handleSave}
                          disabled={!searchValue}
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
                      <Tooltip title={t_i18n('Search')}>
                        <IconButton
                          size="small"
                          onClick={handleSearchIconClick}
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
              }}
            />
            </Box>

            {/* Search Button */}
            <Button
              ref={searchButtonRef}
              variant="contained"
              color="primary"
              onClick={(e) => handleSearch(e)}
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
          <Popover
            open={Boolean(anchorEl)}
            anchorEl={anchorEl}
            onClose={handleClosePopover}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'left',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'left',
            }}
            sx={{
              marginTop: 1,
            }}
            PaperProps={{
              sx: {
                width: anchorEl ? anchorEl.offsetWidth : 400,
                maxWidth: '90vw',
              },
            }}
          >
            <Paper sx={{ width: '100%' }}>
              <Box sx={{ padding: 2 }}>
                <Typography
                  variant="subtitle1"
                  sx={{
                    fontWeight: 600,
                    marginBottom: 1.5,
                  }}
                >
                  {t_i18n('Recent searches')}
                </Typography>
                <List dense sx={{ padding: 0 }}>
                  {recentSearches.map((search) => {
                    const isHovered = hoveredItemId === search.id;
                    return (
                    <ListItem
                      key={search.id}
                      component="button"
                      onClick={() => handleSelectRecentSearch(search.query)}
                      onMouseEnter={() => setHoveredItemId(search.id)}
                      onMouseLeave={() => setHoveredItemId(null)}
                      sx={{
                        borderRadius: 1,
                        marginBottom: 0.5,
                        cursor: 'pointer',
                        backgroundColor: isHovered ? '#E3F2FD' : 'rgba(0, 0, 0, 0.02)',
                        border: isHovered ? '1px solid #2196F3' : '1px solid rgba(0, 0, 0, 0.05)',
                        paddingTop: 1.2,
                        paddingBottom: 1.2,
                        minHeight: 36,
                      }}
                    >
                      <History fontSize="small" sx={{ color: 'text.secondary', marginRight: 1 }} />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {search.query}
                        </Typography>
                      </Box>
                      <ListItemSecondaryAction>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Typography variant="caption" color="text.secondary" sx={{ marginRight: 1 }}>
                            {search.timestamp}
                          </Typography>
                          {isHovered && (
                          <Box
                            sx={{
                              display: 'flex',
                              gap: 0.5,
                              alignItems: 'center',
                            }}
                          >
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleSelectRecentSearch(search.query);
                              }}
                              sx={{ padding: 0.5 }}
                            >
                              <Search fontSize="small" sx={{ color: 'text.secondary' }} />
                            </IconButton>
                            <IconButton
                              size="small"
                              onClick={(e) => handleEditSearch(search.query, e)}
                              sx={{ padding: 0.5 }}
                            >
                              <Edit fontSize="small" sx={{ color: 'text.secondary' }} />
                            </IconButton>
                          </Box>
                          )}
                        </Box>
                      </ListItemSecondaryAction>
                    </ListItem>
                    );
                  })}
                </List>
                <Divider sx={{ marginY: 2 }} />
                <Button
                  startIcon={<Save />}
                  variant="outlined"
                  fullWidth
                  onClick={handleSave}
                  sx={{
                    textTransform: 'none',
                    marginBottom: 1,
                  }}
                >
                  {t_i18n('Save Search')}
                </Button>
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{
                    display: 'block',
                    textAlign: 'center',
                    fontSize: '0.75rem',
                  }}
                >
                  {t_i18n('Use arrow keys to navigate and Enter to select')}
                </Typography>
              </Box>
            </Paper>
          </Popover>

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

          {/* Search Results Placeholder */}
          {hasSearched && (
            <Box
              sx={{
                marginTop: 4,
                padding: 2,
                backgroundColor: 'action.hover',
                borderRadius: 1,
                textAlign: 'center',
              }}
            >
              <Typography variant="body2" color="text.secondary">
                {t_i18n('Search results will appear here')}
              </Typography>
            </Box>
          )}
        </Paper>
      </Box>
    </>
  );
};

export default RessaSearch;
