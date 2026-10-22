import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Box, List, ListItemButton, ListItemIcon, ListItemText, Typography } from '@mui/material';
import { ChevronRightOutlined, DescriptionOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useNavSearch, { PLATFORM_SEARCH_PAGE_MAX_RESULTS } from '../nav/useNavSearch';

// "Application pages" card of the search results: deep links to platform pages matching the keyword.
const INITIAL_COUNT = 2;

const NavigationSearchResults = ({ keyword }: { keyword?: string | null }) => {
  const { t_i18n } = useFormatter();
  const results = useNavSearch(keyword);
  const [showAll, setShowAll] = useState(false);
  useEffect(() => setShowAll(false), [keyword]);
  if (results.length === 0) return null;
  const hidden = showAll ? 0 : Math.max(results.length - INITIAL_COUNT, 0);

  return (
    <Box
      sx={{
        mb: 2,
        p: 2,
        border: 1,
        borderColor: 'divider',
        borderRadius: 1,
        bgcolor: 'background.paper',
      }}
    >
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {t_i18n('Application pages')}
      </Typography>
      <List disablePadding>
        {(showAll ? results : results.slice(0, INITIAL_COUNT)).map(({ path, label, parents }) => (
          <ListItemButton key={path} component={Link} to={path} sx={{ borderRadius: 1 }}>
            <ListItemIcon sx={{ minWidth: 48 }}>
              <DescriptionOutlined fontSize="small" />
            </ListItemIcon>
            <ListItemText
              primary={label}
              secondary={parents.join(' > ') || undefined}
            />
            <ChevronRightOutlined fontSize="small" color="disabled" />
          </ListItemButton>
        ))}
      </List>
      {hidden > 0 && (
        <Button variant="tertiary" size="small" onClick={() => setShowAll(true)} sx={{ mt: 1 }}>
          {`${t_i18n('Show more')} (${hidden})`}
        </Button>
      )}
      {showAll && results.length >= PLATFORM_SEARCH_PAGE_MAX_RESULTS && (
        <Typography variant="caption" color="text.secondary" component="p" sx={{ mt: 1 }}>
          {t_i18n('Showing at most {max} pages, refine your search to narrow them down', { values: { max: PLATFORM_SEARCH_PAGE_MAX_RESULTS } })}
        </Typography>
      )}
    </Box>
  );
};

export default NavigationSearchResults;
