import React, { MutableRefObject, useEffect } from 'react';
import { Box, List, ListItemButton, ListItemIcon, ListItemText, Popper } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { Link } from 'react-router';
import { SearchOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import useNavSearch, { NavSearchResult, PLATFORM_SEARCH_PAGE_MAX_RESULTS } from '../nav/useNavSearch';
import NavSearchResultContent from './NavSearchResultContent';

export const NAV_SEARCH_LISTBOX_ID = 'nav-search-suggestions';
export const navSearchOptionId = (index: number) => `${NAV_SEARCH_LISTBOX_ID}-option-${index}`;

interface NavSearchSuggestionsProps {
  keyword: string;
  anchorEl: HTMLElement | null;
  /** Row highlighted by the keyboard, -1 for none. The "Search" row is first (0), pages follow. */
  activeIndex: number;
  /** Written with the displayed pages, so the parent's key handler can resolve the highlighted row. */
  itemsRef: MutableRefObject<NavSearchResult[]>;
  /** A page row was clicked: only closes the dropdown, the row is a link that navigates by itself. */
  onPageClick: () => void;
  onSearch: () => void;
}

// FDS-WORKAROUND #78: MUI Popper, no library field pairs a free-text search with a suggestions list — see fds-migration/LIBRARY-FEEDBACK.md #78
// Mounted only while open: the pages search is not computed for a closed dropdown.
const NavSearchSuggestions = ({ keyword, anchorEl, activeIndex, itemsRef, onPageClick, onSearch }: NavSearchSuggestionsProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const pages = useNavSearch(keyword).slice(0, PLATFORM_SEARCH_PAGE_MAX_RESULTS);

  useEffect(() => {
    itemsRef.current = pages;
  });
  useEffect(() => () => {
    itemsRef.current = [];
  }, []);
  useEffect(() => {
    document.getElementById(navSearchOptionId(activeIndex))?.scrollIntoView?.({ block: 'nearest' });
  }, [activeIndex]);

  return (
    <Popper
      open
      anchorEl={anchorEl}
      placement="bottom-start"
      style={{ width: anchorEl?.clientWidth, zIndex: theme.zIndex.modal }}
    >
      <Box
        // Keeps the focus in the input: a click on a row must not blur it first.
        onMouseDown={(event) => event.preventDefault()}
        sx={{
          mt: 0.5,
          maxHeight: '60vh',
          overflowY: 'auto',
          border: 1,
          borderColor: 'divider',
          borderRadius: 1,
          bgcolor: 'background.paper',
          boxShadow: 8,
        }}
      >
        <List id={NAV_SEARCH_LISTBOX_ID} role="listbox" aria-label={t_i18n('Suggestions')} disablePadding>
          <ListItemButton
            id={navSearchOptionId(0)}
            role="option"
            tabIndex={-1}
            aria-selected={activeIndex === 0}
            selected={activeIndex === 0}
            onClick={onSearch}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>
              <SearchOutlined fontSize="small" />
            </ListItemIcon>
            <ListItemText primary={`${t_i18n('Search')}: ${keyword}`} />
          </ListItemButton>
          {pages.map(({ path, label, parents }, index) => (
            // A real link: the Link navigates (plain click) and the browser handles Cmd/Ctrl-click (new tab).
            <ListItemButton
              key={path}
              component={Link}
              to={path}
              id={navSearchOptionId(index + 1)}
              role="option"
              tabIndex={-1}
              aria-selected={index + 1 === activeIndex}
              selected={index + 1 === activeIndex}
              onClick={onPageClick}
            >
              <NavSearchResultContent label={label} parents={parents} iconWidth={40} />
            </ListItemButton>
          ))}
        </List>
      </Box>
    </Popper>
  );
};

export default NavSearchSuggestions;
