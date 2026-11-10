import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Box, List, ListItemButton } from '@mui/material';
import { Text } from '@filigran/design-system';
import { ChevronRightOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useNavSearch, { PLATFORM_SEARCH_PAGE_MAX_RESULTS } from '../nav/useNavSearch';
import NavSearchResultContent from './NavSearchResultContent';

// "Application pages" card of the search results: deep links to platform pages matching the keyword.
const INITIAL_COUNT = 2;
const TITLE_ID = 'nav-search-results-title';

const NavigationSearchResults = ({ keyword }: { keyword?: string | null }) => {
  const { t_i18n } = useFormatter();
  const matches = useNavSearch(keyword);
  const [showAll, setShowAll] = useState(false);
  useEffect(() => setShowAll(false), [keyword]);
  if (matches.length === 0) return null;
  const results = matches.slice(0, PLATFORM_SEARCH_PAGE_MAX_RESULTS);
  const isCut = matches.length > PLATFORM_SEARCH_PAGE_MAX_RESULTS;
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
      <Text id={TITLE_ID} variant="content-compact" as="h2" style={{ margin: 0, marginBottom: 8 }}>
        {t_i18n('Application pages')}
      </Text>
      <List disablePadding aria-labelledby={TITLE_ID}>
        {(showAll ? results : results.slice(0, INITIAL_COUNT)).map(({ path, label, parents }) => (
          <ListItemButton key={path} component={Link} to={path} sx={{ borderRadius: 1 }}>
            <NavSearchResultContent label={label} parents={parents} iconWidth={48} />
            <ChevronRightOutlined fontSize="small" color="disabled" />
          </ListItemButton>
        ))}
      </List>
      {hidden > 0 && (
        <Button variant="tertiary" size="small" onClick={() => setShowAll(true)} sx={{ mt: 1 }}>
          {`${t_i18n('Show more')} (${hidden})`}
        </Button>
      )}
      {showAll && isCut && (
        <Text variant="content-caption" as="p" style={{ margin: 0, marginTop: 8 }}>
          {t_i18n('Showing at most {max} pages, refine your search to narrow them down', { values: { max: PLATFORM_SEARCH_PAGE_MAX_RESULTS } })}
        </Text>
      )}
    </Box>
  );
};

export default NavigationSearchResults;
