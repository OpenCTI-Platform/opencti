import React, { MutableRefObject, useEffect } from 'react';
import { Box, List, ListItemButton, ListItemIcon, ListItemText, Popper } from '@mui/material';
import { DescriptionOutlined, SearchOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';
import useNavSearch, { NavSearchResult } from '../nav/useNavSearch';

export const NAV_SEARCH_LISTBOX_ID = 'nav-search-suggestions';
export const navSearchOptionId = (index: number) => `${NAV_SEARCH_LISTBOX_ID}-option-${index}`;

interface NavSearchSuggestionsProps {
  keyword: string;
  anchorEl: HTMLElement | null;
  /** Row highlighted by the keyboard, -1 for none. Pages come first, the "Search" row is last. */
  activeIndex: number;
  /** Written with the displayed pages, so the parent's key handler can resolve the highlighted row. */
  itemsRef: MutableRefObject<NavSearchResult[]>;
  onSelectPage: (path: string) => void;
  onSearch: () => void;
}

// FDS-WORKAROUND #71: MUI Popper, no library field pairs a free-text search with a suggestions list — see fds-migration/LIBRARY-FEEDBACK.md #71
// Mounted only while open: the pages search is not computed for a closed dropdown.
const NavSearchSuggestions = ({ keyword, anchorEl, activeIndex, itemsRef, onSelectPage, onSearch }: NavSearchSuggestionsProps) => {
  const { t_i18n } = useFormatter();
  const pages = useNavSearch(keyword);

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
      style={{ width: anchorEl?.clientWidth, zIndex: 1300 }}
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
        <List id={NAV_SEARCH_LISTBOX_ID} role="listbox" disablePadding>
          {pages.map(({ path, label, parents }, index) => (
            <ListItemButton
              key={path}
              id={navSearchOptionId(index)}
              role="option"
              aria-selected={index === activeIndex}
              selected={index === activeIndex}
              onClick={() => onSelectPage(path)}
            >
              <ListItemIcon sx={{ minWidth: 40 }}>
                <DescriptionOutlined fontSize="small" />
              </ListItemIcon>
              <ListItemText primary={label} secondary={parents.join(' > ') || undefined} />
            </ListItemButton>
          ))}
          <ListItemButton
            id={navSearchOptionId(pages.length)}
            role="option"
            aria-selected={pages.length === activeIndex}
            selected={pages.length === activeIndex}
            onClick={onSearch}
          >
            <ListItemIcon sx={{ minWidth: 40 }}>
              <SearchOutlined fontSize="small" />
            </ListItemIcon>
            <ListItemText primary={`${t_i18n('Search')}: ${keyword}`} />
          </ListItemButton>
        </List>
      </Box>
    </Popper>
  );
};

export default NavSearchSuggestions;
