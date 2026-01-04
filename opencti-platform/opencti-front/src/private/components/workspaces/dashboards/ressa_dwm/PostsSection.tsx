import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Tabs,
  Tab,
  Chip,
  TextField,
  InputAdornment,
  Button,
  Typography,
  IconButton,
  Menu,
  MenuItem,
  Pagination,
  Stack,
} from '@mui/material';
import {
  Search as SearchIcon,
  Add as AddIcon,
  Star as StarIcon,
  ArrowDropDown as ArrowDropDownIcon,
  MenuOutlined as MenuIcon,
  AccessTime as ClockIcon,
} from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../components/Theme';
import { useFormatter } from '../../../../../components/i18n';
import { usePostsData, type Post } from './usePostsData';
import Loader from '../../../../../components/Loader';
import PostsTableRenderer from './PostsTableRenderer';

const PostsSection: React.FC = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState<number>(1);
  const [searchText, setSearchText] = useState<string>('');
  const [searchTypeAnchor, setSearchTypeAnchor] = useState<null | HTMLElement>(null);
  const [page, setPage] = useState<number>(1);
  const itemsPerPage = 10;

  // Fetch data from API
  const { data: currentTabData, total, loading, error } = usePostsData({
    tab: currentTab,
    page,
    perPage: itemsPerPage,
    filters: [],
    searchText,
  });

  const hasData = !loading && currentTabData.length > 0;

  const tabs = [
    { label: 'Telegram Recents', value: 0 },
    { label: 'Exploid Posts', value: 1 },
    { label: 'Russian Market Items', value: 2 },
    { label: 'IntelX Leaks', value: 3 },
    { label: 'IntelX Items', value: 4 },
  ];

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
    setPage(1); // Reset to first page when changing tabs
  };

  const handleSearchTypeClick = (event: React.MouseEvent<HTMLElement>) => {
    setSearchTypeAnchor(event.currentTarget);
  };

  const handleSearchTypeClose = () => {
    setSearchTypeAnchor(null);
  };

  // Calculate pagination
  const totalPages = Math.ceil(total / itemsPerPage);
  const startIndex = (page - 1) * itemsPerPage;
  const endIndex = Math.min(startIndex + itemsPerPage, total);
  const currentPosts = currentTabData; // Data is already paginated by the API

  const handleResetFilters = () => {
    setSearchText('');
    setPage(1);
  };

  return (
    <Card
      variant="outlined"
      sx={{
        marginTop: 3,
        backgroundColor: theme.palette.background?.paper || theme.palette.background?.default,
      }}
    >
      <CardContent sx={{ padding: 0 }}>
        {/* Tabs Section */}
        <Box
          sx={{
            borderBottom: 1,
            borderColor: 'divider',
            paddingX: 2,
          }}
        >
          <Tabs
            value={currentTab}
            onChange={handleTabChange}
            sx={{
              '& .MuiTab-root': {
                textTransform: 'none',
                fontSize: '0.875rem',
                fontWeight: 500,
                minHeight: 48,
                paddingX: 2,
                color: theme.palette.text?.secondary,
              },
              '& .Mui-selected': {
                color: theme.palette.primary.main,
              },
              '& .MuiTabs-indicator': {
                backgroundColor: theme.palette.primary.main,
              },
            }}
          >
            {tabs.map((tab) => (
              <Tab key={tab.value} label={tab.label} />
            ))}
          </Tabs>
        </Box>

        {/* Filters and Search Section */}
        <Box
          sx={{
            padding: 2,
            display: 'flex',
            alignItems: 'center',
            gap: 2,
            borderBottom: 1,
            borderColor: 'divider',
            flexWrap: 'wrap',
          }}
        >
          {/* Filter Pills */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
            <Chip
              icon={<ClockIcon sx={{ fontSize: '0.875rem !important', color: '#fff !important' }} />}
              label="Filter"
              size="small"
              sx={{
                backgroundColor: theme.palette.mode === 'dark' ? '#424242' : '#616161',
                color: '#fff',
                fontSize: '0.75rem',
                height: 24,
                paddingX: 1,
                '& .MuiChip-icon': {
                  color: '#fff !important',
                },
              }}
            />
            <Chip
              icon={<StarIcon sx={{ fontSize: '0.875rem !important' }} />}
              label="Filter"
              size="small"
              variant="outlined"
              sx={{
                fontSize: '0.75rem',
                height: 24,
                borderColor: theme.palette.divider,
                paddingX: 1,
              }}
            />
            <IconButton
              size="small"
              sx={{
                width: 24,
                height: 24,
                color: theme.palette.text?.secondary,
              }}
            >
              <AddIcon sx={{ fontSize: '1rem' }} />
            </IconButton>
          </Box>

          {/* Search Section */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <TextField
              placeholder="Text"
              size="small"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon sx={{ fontSize: '1.25rem', color: theme.palette.text?.secondary }} />
                  </InputAdornment>
                ),
              }}
              sx={{
                width: 200,
                '& .MuiOutlinedInput-root': {
                  fontSize: '0.875rem',
                },
              }}
            />
            <Button
              variant="outlined"
              startIcon={<MenuIcon />}
              endIcon={<ArrowDropDownIcon />}
              onClick={handleSearchTypeClick}
              sx={{
                textTransform: 'none',
                fontSize: '0.875rem',
                minWidth: 80,
              }}
            >
              Text
            </Button>
            <Menu
              anchorEl={searchTypeAnchor}
              open={Boolean(searchTypeAnchor)}
              onClose={handleSearchTypeClose}
            >
              <MenuItem onClick={handleSearchTypeClose}>Text</MenuItem>
              <MenuItem onClick={handleSearchTypeClose}>Title</MenuItem>
              <MenuItem onClick={handleSearchTypeClose}>Category</MenuItem>
            </Menu>
            <Button
              variant="contained"
              sx={{
                textTransform: 'none',
                fontSize: '0.875rem',
                paddingX: 2,
              }}
            >
              Explore More
            </Button>
          </Box>
        </Box>

        {/* Table Section */}
        <Box>
          {loading ? (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                padding: 8,
                minHeight: 400,
              }}
            >
              <Loader />
            </Box>
          ) : hasData ? (
            <PostsTableRenderer tab={currentTab} data={currentPosts} theme={theme} />
          ) : (
            /* Empty State */
            <Box
              sx={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: 8,
                minHeight: 400,
              }}
            >
              <Box
                sx={{
                  width: 120,
                  height: 120,
                  borderRadius: '50%',
                  backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.04)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: 3,
                }}
              >
                <SearchIcon
                  sx={{
                    fontSize: '3rem',
                    color: theme.palette.text?.secondary,
                  }}
                />
              </Box>
              <Typography
                variant="h6"
                sx={{
                  fontWeight: 600,
                  fontSize: '1.25rem',
                  marginBottom: 1,
                  color: theme.palette.text?.primary,
                }}
              >
                {t_i18n('Nothing Found!')}
              </Typography>
              <Typography
                variant="body2"
                sx={{
                  color: theme.palette.text?.secondary,
                  marginBottom: 4,
                  fontSize: '0.875rem',
                }}
              >
                {t_i18n('Change your filters or reset them all')}
              </Typography>
              <Button
                variant="contained"
                onClick={handleResetFilters}
                sx={{
                  textTransform: 'none',
                  fontSize: '0.875rem',
                  paddingX: 3,
                  paddingY: 1,
                }}
              >
                {t_i18n('Reset Filters')}
              </Button>
            </Box>
          )}
        </Box>

        {/* Pagination Section */}
        {hasData && (
          <Box
            sx={{
              padding: 2,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderTop: 1,
              borderColor: 'divider',
              flexWrap: 'wrap',
              gap: 2,
            }}
          >
            <Typography
              variant="body2"
              sx={{
                color: theme.palette.text?.secondary,
                fontSize: '0.875rem',
              }}
            >
              Showing {startIndex + 1}-{endIndex} of {total} items
            </Typography>
            <Stack spacing={2}>
              <Pagination
                count={totalPages}
                page={page}
                onChange={(_, value) => setPage(value)}
                color="primary"
                size="small"
                showFirstButton
                showLastButton
                siblingCount={1}
                boundaryCount={1}
                sx={{
                  '& .MuiPaginationItem-root': {
                    fontSize: '0.875rem',
                  },
                }}
              />
            </Stack>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default PostsSection;
