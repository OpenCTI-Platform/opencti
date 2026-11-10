import React from 'react';
import { ListItemIcon, ListItemText } from '@mui/material';
import { DescriptionOutlined } from '@mui/icons-material';
import type { NavSearchResult } from '../nav/useNavSearch';

// Icon + label + breadcrumb of a page result, shared by the top bar dropdown and the search page card.
const NavSearchResultContent = ({ label, parents, iconWidth }: Pick<NavSearchResult, 'label' | 'parents'> & { iconWidth: number }) => (
  <>
    <ListItemIcon sx={{ minWidth: iconWidth }}>
      <DescriptionOutlined fontSize="small" />
    </ListItemIcon>
    <ListItemText primary={label} secondary={parents.join(' > ') || undefined} />
  </>
);

export default NavSearchResultContent;
