import React from 'react';
import { Box, ListItemIcon, ListItemText } from '@mui/material';
import { DescriptionOutlined, SearchOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import type { NavSearchResult } from '../nav/useNavSearch';

// Icon + label + breadcrumb of a page result, shared by the top bar dropdown and the search page card.
// When the label and breadcrumb do not say why the page matches, the matched keywords are shown on the right.
const NavSearchResultContent = ({ label, parents, hints, iconWidth }: Pick<NavSearchResult, 'label' | 'parents' | 'hints'> & { iconWidth: number }) => (
  <>
    <ListItemIcon sx={{ minWidth: iconWidth }}>
      <DescriptionOutlined fontSize="small" />
    </ListItemIcon>
    <ListItemText primary={label} secondary={parents.join(' > ') || undefined} />
    {hints && hints.length > 0 && (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, ml: 2, maxWidth: '40%', color: 'text.secondary' }}>
        <SearchOutlined sx={{ fontSize: 16, flexShrink: 0 }} />
        <Text
          variant="content-compact"
          as="span"
          style={{ color: 'inherit', fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 2 }}
        >
          {hints.map((hint) => `“${hint}”`).join(', ')}
        </Text>
      </Box>
    )}
  </>
);

export default NavSearchResultContent;
